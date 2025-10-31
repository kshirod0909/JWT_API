CREATE TABLE [dbo].[Users](
    [Id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
    [Email] NVARCHAR(256) NOT NULL UNIQUE,
    [PasswordHash] VARBINARY(MAX) NOT NULL, -- store Argon2 output (or store as base64)
    [PasswordSalt] VARBINARY(128) NOT NULL,
    [Role] NVARCHAR(50) NULL,
    [IsLocked] BIT NOT NULL DEFAULT 0,
    [FailedLoginCount] INT NOT NULL DEFAULT 0,
    [LockoutEndUtc] DATETIME2 NULL,
    [CreatedAtUtc] DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE [dbo].[RefreshTokens] (
    [Id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
    [UserId] UNIQUEIDENTIFIER NOT NULL,
    [TokenHash] VARBINARY(MAX) NOT NULL, -- store hashed refresh token (not plain)
    [CreatedAtUtc] DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    [ExpiresAtUtc] DATETIME2 NOT NULL,
    [RevokedAtUtc] DATETIME2 NULL,
    [RevokedByIp] NVARCHAR(50) NULL,
    CONSTRAINT FK_RefreshTokens_User FOREIGN KEY (UserId) REFERENCES Users(Id)
);

CREATE INDEX IX_RefreshTokens_UserId ON RefreshTokens(UserId);
