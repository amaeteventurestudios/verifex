const dns = require('dns').promises;
const http = require('http');
const net = require('net');
const express = require('express');

const PORT = 3001;
const FORMAT_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SMTP_TIMEOUT_MS = 10000;

const app = express();

function result(email, status, details) {
  return {
    email,
    status,
    details: {
      formatValid: Boolean(details.formatValid),
      mxFound: Boolean(details.mxFound),
      mxHost: details.mxHost || null,
      smtpCode: Number.isInteger(details.smtpCode) ? details.smtpCode : null,
      smtpMessage: details.smtpMessage || null,
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

function isCompleteSmtpResponse(raw) {
  const lines = raw.split(/\r?\n/).filter(Boolean);
  return lines.some((line) => /^\d{3}\s/.test(line));
}

function parseSmtpCode(raw) {
  const lines = raw.split(/\r?\n/).filter(Boolean).reverse();
  const line = lines.find((entry) => /^\d{3}[\s-]/.test(entry));
  return line ? Number.parseInt(line.slice(0, 3), 10) : null;
}

function mapSmtpStatus(code) {
  if (code === 250) {
    return 'Valid';
  }

  if ([550, 551, 553].includes(code)) {
    return 'Invalid Mailbox';
  }

  if ([421, 450, 451, 452].includes(code)) {
    return 'Unable to Confirm (Try Again)';
  }

  return 'Unable to Confirm';
}

function smtpProbe(mxHost, email) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: mxHost, port: 25 });
    let buffer = '';
    let settled = false;
    let waiter = null;

    function finish(payload, closeMode = 'destroy') {
      if (settled) {
        return;
      }

      settled = true;

      if (closeMode === 'end') {
        socket.end();
      } else {
        socket.destroy();
      }

      resolve({
        smtpCode: Number.isInteger(payload.smtpCode) ? payload.smtpCode : null,
        smtpMessage: payload.smtpMessage || null,
      });
    }

    function releaseWaiterIfReady() {
      if (!waiter || !isCompleteSmtpResponse(buffer)) {
        return;
      }

      const response = buffer;
      buffer = '';
      const resolveWaiter = waiter;
      waiter = null;
      resolveWaiter(response);
    }

    function waitForResponse() {
      return new Promise((resolveWaiter) => {
        waiter = resolveWaiter;
        releaseWaiterIfReady();
      });
    }

    socket.setEncoding('utf8');
    socket.setTimeout(SMTP_TIMEOUT_MS);

    socket.on('data', (chunk) => {
      buffer += chunk;
      releaseWaiterIfReady();
    });

    socket.on('timeout', () => {
      finish({
        smtpCode: null,
        smtpMessage: `SMTP connection timed out after ${SMTP_TIMEOUT_MS}ms`,
      });
    });

    socket.on('error', (error) => {
      finish({
        smtpCode: null,
        smtpMessage: `SMTP connection failed: ${error.code || error.message}`,
      });
    });

    socket.on('close', () => {
      if (!settled) {
        finish({
          smtpCode: null,
          smtpMessage: 'SMTP connection closed before verification completed',
        });
      }
    });

    socket.on('connect', async () => {
      try {
        const greeting = await waitForResponse();
        if (settled) {
          return;
        }

        if (parseSmtpCode(greeting) !== 220) {
          finish({
            smtpCode: null,
            smtpMessage: `SMTP greeting did not return 220: ${greeting.trim()}`,
          });
          return;
        }

        socket.write('EHLO verifier.local\r\n');
        const ehloResponse = await waitForResponse();
        if (settled) {
          return;
        }

        const ehloCode = parseSmtpCode(ehloResponse);
        if (ehloCode < 200 || ehloCode >= 400) {
          finish({
            smtpCode: null,
            smtpMessage: `SMTP EHLO failed: ${ehloResponse.trim()}`,
          });
          return;
        }

        socket.write('MAIL FROM:<verify@verifier.local>\r\n');
        const mailFromResponse = await waitForResponse();
        if (settled) {
          return;
        }

        const mailFromCode = parseSmtpCode(mailFromResponse);
        if (mailFromCode < 200 || mailFromCode >= 400) {
          finish({
            smtpCode: null,
            smtpMessage: `SMTP MAIL FROM failed: ${mailFromResponse.trim()}`,
          });
          return;
        }

        socket.write(`RCPT TO:<${email}>\r\n`);
        const rcptResponse = await waitForResponse();
        const rcptCode = parseSmtpCode(rcptResponse);

        if (!settled) {
          socket.write('QUIT\r\n', () => {
            finish(
              {
                smtpCode: rcptCode,
                smtpMessage: rcptResponse.trim(),
              },
              'end'
            );
          });
        }
      } catch (error) {
        finish({
          smtpCode: null,
          smtpMessage: `SMTP probe failed: ${error.message}`,
        });
      }
    });
  });
}

async function verifyEmail(email) {
  if (!FORMAT_REGEX.test(email)) {
    return result(email, 'Invalid Format', {
      formatValid: false,
      mxFound: false,
      mxHost: null,
      smtpCode: null,
      smtpMessage: null,
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
    });
  }

  if (!Array.isArray(mxRecords) || mxRecords.length === 0) {
    return result(email, 'Invalid Domain', {
      formatValid: true,
      mxFound: false,
      mxHost: null,
      smtpCode: null,
      smtpMessage: 'No MX records found',
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
    });
  }

  const smtp = await smtpProbe(mxHost, email);

  return result(email, mapSmtpStatus(smtp.smtpCode), {
    formatValid: true,
    mxFound: true,
    mxHost,
    smtpCode: smtp.smtpCode,
    smtpMessage: smtp.smtpMessage,
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
