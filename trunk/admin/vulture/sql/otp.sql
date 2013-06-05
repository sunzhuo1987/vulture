PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE "otp" (
    "id" integer NOT NULL PRIMARY KEY,
    "name" varchar(128) NOT NULL,
    "ldap_id" integer NOT NULL REFERENCES "ldap" ("id"),
    "script" text NOT NULL,
    "passlen" integer NOT NULL,
    "template" text NOT NULL
);
INSERT INTO "otp" VALUES(1,'otp (de test)',1,'echo {{number}}>>{{message}} | /usr/bin/mail -s "OTP PASS" etiennehelluy@gmail.com',8,'Hello {{user}}! here is your password : {{pass}}',3601);
CREATE INDEX "otp_2b44c679" ON "otp" ("ldap_id");
COMMIT;
