-- Fix invalid admin password hash
UPDATE users 
SET password_hash = '$argon2id$v=19$m=19456,t=2,p=1$OVWvHbVirbpSvYpsrDT3Kw$izbWmzByDZDv1u4KcTgKcqC830lUm0UfKkqEpX9d50c'
WHERE email = 'admin@example.com';
