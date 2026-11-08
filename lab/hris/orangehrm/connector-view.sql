-- =============================================================================
-- connector-view.sql - the ONLY thing the HR connector can read.
-- -----------------------------------------------------------------------------
-- The provisioning feed needs eight HR fields per worker. This view has
-- exactly those, and hris.sh grants the connector's account SELECT on this
-- view and nothing else (no table, no other schema). So the database itself
-- enforces "least data": a date of birth, home address, salary, national ID,
-- phone, photo, note or termination reason can never reach the connector or
-- Microsoft, whatever the connector's code does.
--
-- SQL SECURITY DEFINER: the view reads OrangeHRM's tables with its owner's
-- rights; the caller needs rights on the view only.
--
--   employee_id       OrangeHRM "Employee Id"          -> SCIM externalId / employeeNumber
--   first_name        "First Name"                     -> name.givenName
--   last_name         "Last Name"                      -> name.familyName
--   department        Job > "Sub Unit"                 -> department
--   job_title         Job > "Job Title"                -> title
--   manager_id        Report-to > Supervisor (Direct)'s Employee Id -> manager
--   joined_date       Job > "Joined Date"              -> hireDate
--   termination_date  Terminate Employment > date      -> leaver (active:false) on that day
--
-- Purged employees (OrangeHRM's GDPR purge) are left out.
-- =============================================================================
CREATE DATABASE IF NOT EXISTS hr_feed;

CREATE OR REPLACE SQL SECURITY DEFINER VIEW hr_feed.v_worker_feed AS
SELECT
  e.employee_id                                   AS employee_id,
  e.emp_firstname                                 AS first_name,
  e.emp_lastname                                  AS last_name,
  s.name                                          AS department,
  j.job_title                                     AS job_title,
  (SELECT MIN(m.employee_id)
     FROM orangehrm.hs_hr_emp_reportto r
     JOIN orangehrm.hs_hr_employee m ON m.emp_number = r.erep_sup_emp_number AND m.purged_at IS NULL
    WHERE r.erep_sub_emp_number = e.emp_number AND r.erep_reporting_mode = 1) AS manager_id,
  e.joined_date                                   AS joined_date,
  t.termination_date                              AS termination_date
FROM orangehrm.hs_hr_employee e
LEFT JOIN orangehrm.ohrm_subunit s          ON s.id = e.work_station
LEFT JOIN orangehrm.ohrm_job_title j        ON j.id = e.job_title_code
LEFT JOIN orangehrm.ohrm_emp_termination t  ON t.id = e.termination_id
WHERE e.purged_at IS NULL;
