-- Introduce the global_admin role.
-- Existing rows in user_roles with role='admin' were system-wide super-admins
-- (the global Admin role gated company CRUD and user management). Move them to
-- 'global_admin' so they keep those powers under the new naming, while the
-- per-company role 'admin' in user_companies remains untouched.
UPDATE user_roles
SET role = 'global_admin'
WHERE role = 'admin';
