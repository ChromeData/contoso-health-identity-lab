// =============================================================================
// hris.mjs - read OrangeHRM's provisioning view (and nothing else).
// -----------------------------------------------------------------------------
// The connector signs in to OrangeHRM's MariaDB as `hr_connector`. That
// account can SELECT one view, hr_feed.v_worker_feed (eight HR fields per
// worker; ../orangehrm/connector-view.sql). MariaDB refuses every other
// table, so the connector cannot read a date of birth, address or salary
// even by mistake.
//
// The password lives ONLY in the macOS Keychain (item contoso-hris-connector,
// made by ../orangehrm/hris.sh). It is read with `security ... -w` into this
// process's memory: never argv, never the environment, never printed.
// The database listens on 127.0.0.1 only.
//
// mysql2 is loaded lazily, so the tests (which never touch a database) run
// with no npm install.
// =============================================================================
import { execFile } from 'node:child_process';

export function keychainSecret(service) {
  return new Promise((resolve, reject) => {
    execFile('security', ['find-generic-password', '-s', service, '-w'], (err, stdout) => {
      if (err) return reject(new Error(`Keychain item ${service} not found. Run lab/hris/orangehrm/hris.sh up, then hris.sh connector.`));
      resolve(String(stdout).replace(/\n$/, ''));
    });
  });
}

export async function readHris({ host = '127.0.0.1', port = 3307, user = 'hr_connector', secret = 'contoso-hris-connector' } = {}) {
  const { default: mysql } = await import('mysql2/promise');
  const conn = await mysql.createConnection({ host, port, user, password: await keychainSecret(secret), dateStrings: true, connectTimeout: 10000 });
  try {
    const [rows] = await conn.query('SELECT employee_id, first_name, last_name, department, job_title, manager_id, joined_date, termination_date FROM hr_feed.v_worker_feed');
    return rows;
  } finally {
    await conn.end();
  }
}
