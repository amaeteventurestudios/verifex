const dns = require('dns').promises;
const http = require('http');
const express = require('express');
const fetch = require('node-fetch');

const PORT = 3001;
const FORMAT_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Primary verifier: Verifalia
// TODO: move to environment variables
const VERIFALIA_SID = '77140bea-25e9-47af-b57c-ba140bf4d47c';
const VERIFALIA_PASSWORD = 'pbH7Y4KTC3sRtNq'; // user must fill this in
const VERIFALIA_QUALITY = 'High';

// Fallback verifier: ZeroBounce
const ZEROBOUNCE_API_KEY = '51342ada52b74019aeab6088be3c4a73';

const app = express();

function result(email, status, details) {
  return {
    email,
    status,
    details: {
      formatValid: Boolean(details.formatValid),
      mxFound: Boolean(details.mxFound),
      mxHost: details.mxHost || null,
      smtpCode: details.smtpCode === undefined ? null : details.smtpCode,
      smtpMessage: details.smtpMessage || null,
      provider: details.provider || 'None',
    },
  };
}

function corsHeaders(_req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
}

function sendJson(res, statusCode, payload) {
  res.status(statusCode).type('application/json; charset=utf-8').send(payload);
}

async function verifyMailbox(email) {
  try {
    const auth = Buffer.from(`${VERIFALIA_SID}:${VERIFALIA_PASSWORD}`).toString('base64');
    const response = await fetch('https://api.verifalia.com/v2.7/email-validations', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        entries: [{ inputData: email }],
        quality: VERIFALIA_QUALITY,
      }),
    });

    const data = await response.json();

    if (response.status === 403 || response.status === 429) {
      throw new Error('Verifalia credits exhausted');
    }

    if (!response.ok) {
      throw new Error(`Verifalia request failed with HTTP ${response.status}`);
    }

    const entry = data && data.entries && data.entries[0] ? data.entries[0] : null;
    const classification = entry && entry.classification;
    const rawStatus = entry && entry.status;
    const statusMap = {
      'Deliverable': 'Valid',
      'Undeliverable': 'Invalid Mailbox',
      'Risky': 'Unable to Confirm',
      'Unknown': 'Unable to Confirm',
    };

    return {
      status: statusMap[classification] || 'Unable to Confirm',
      provider: 'Verifalia',
      smtpCode: null,
      smtpMessage: `Verifalia: ${classification || 'Unknown'} (${rawStatus || 'no detail'})`,
    };
  } catch (verifError) {
    try {
      const zbUrl = `https://api.zerobounce.net/v2/validate?api_key=${ZEROBOUNCE_API_KEY}&email=${encodeURIComponent(email)}`;
      const zbResponse = await fetch(zbUrl);
      const zbData = await zbResponse.json();
      const zbStatusMap = {
        'valid': 'Valid',
        'invalid': 'Invalid Mailbox',
        'catch-all': 'Unable to Confirm',
        'unknown': 'Unable to Confirm',
        'spamtrap': 'Invalid Mailbox',
        'abuse': 'Invalid Mailbox',
        'do_not_mail': 'Invalid Mailbox',
      };

      if (!zbResponse.ok) {
        throw new Error(`ZeroBounce request failed with HTTP ${zbResponse.status}`);
      }

      return {
        status: zbStatusMap[zbData.status] || 'Unable to Confirm',
        provider: 'ZeroBounce',
        smtpCode: null,
        smtpMessage: `ZeroBounce: ${zbData.status} (${zbData.sub_status || 'no detail'})`,
      };
    } catch (zbError) {
      return {
        status: 'Unable to Confirm',
        provider: 'None',
        smtpCode: null,
        smtpMessage: `Both providers failed: ${zbError.message}`,
      };
    }
  }
}

async function verifyEmail(email) {
  if (!FORMAT_REGEX.test(email)) {
    return result(email, 'Invalid Format', {
      formatValid: false,
      mxFound: false,
      mxHost: null,
      smtpCode: null,
      smtpMessage: null,
      provider: 'None',
    });
  }

  const domain = email.split('@').pop().toLowerCase();
  let mxRecords = [];

  try {
    mxRecords = await dns.resolveMx(domain);
  } catch (error) {
    return result(email, 'Invalid Domain', {
      formatValid: true,
      mxFound: false,
      mxHost: null,
      smtpCode: null,
      smtpMessage: `MX lookup failed: ${error.code || error.message}`,
      provider: 'None',
    });
  }

  if (!Array.isArray(mxRecords) || mxRecords.length === 0) {
    return result(email, 'Invalid Domain', {
      formatValid: true,
      mxFound: false,
      mxHost: null,
      smtpCode: null,
      smtpMessage: 'No MX records found',
      provider: 'None',
    });
  }

  mxRecords.sort((a, b) => a.priority - b.priority);
  const mxHost = mxRecords[0].exchange;

  if (!mxHost) {
    return result(email, 'Invalid Domain', {
      formatValid: true,
      mxFound: false,
      mxHost: null,
      smtpCode: null,
      smtpMessage: 'MX record did not include an exchange host',
      provider: 'None',
    });
  }

  const smtp = await verifyMailbox(email);

  return result(email, smtp.status, {
    formatValid: true,
    mxFound: true,
    mxHost,
    smtpCode: smtp.smtpCode,
    smtpMessage: smtp.smtpMessage,
    provider: smtp.provider,
  });
}

app.use(corsHeaders);
app.use(express.json({ limit: '1mb' }));

app.options('*', (_req, res) => {
  res.status(204).end();
});

app.post('/verify', async (req, res) => {
  try {
    const email = String((req.body && req.body.email) || '').trim();
    const payload = await verifyEmail(email);
    sendJson(res, 200, payload);
  } catch (error) {
    sendJson(
      res,
      200,
      result('', 'Unable to Confirm', {
        formatValid: false,
        mxFound: false,
        mxHost: null,
        smtpCode: null,
        smtpMessage: `Unexpected verification error: ${error.message}`,
        provider: 'None',
      })
    );
  }
});

app.use((error, _req, res, next) => {
  if (res.headersSent) {
    next(error);
    return;
  }

  sendJson(
    res,
    200,
    result('', 'Unable to Confirm', {
      formatValid: false,
      mxFound: false,
      mxHost: null,
      smtpCode: null,
      smtpMessage: `Request parsing failed: ${error.message}`,
      provider: 'None',
    })
  );
});

app.use((_req, res) => {
  sendJson(
    res,
    404,
    result('', 'Invalid Format', {
      formatValid: false,
      mxFound: false,
      mxHost: null,
      smtpCode: null,
      smtpMessage: 'Route not found',
      provider: 'None',
    })
  );
});

const server = http.createServer(app);

server.listen(PORT, () => {
  console.log(`VERIFEX SMTP verifier listening on port ${PORT}`);
});

process.on('unhandledRejection', (error) => {
  console.error('Unhandled rejection:', error);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
});
