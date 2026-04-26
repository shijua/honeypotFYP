window.NB_PORTAL_CONFIG = {
  apiBase: "/api/v1",
  invoiceEndpoint: "/api/v1/invoices",
  adminStatusEndpoint: "/admin/status",
  internalGitHost: "git.internal.local",
  internalDbHost: "db01.internal.local",
  honeytokens: {
    INTERNAL_API_KEY: "DECOY_INTERNAL_API_KEY_PUBLIC_SURFACE",
    GITEA_TOKEN: "DECOY_GITEA_TOKEN_PUBLIC_SURFACE",
    BACKUP_READER_PASSWORD: "DECOY_BACKUP_READER_PASSWORD"
  }
};

document.addEventListener("submit", (event) => {
  if (event.target.matches("form[action='/api/v1/login']")) {
    event.preventDefault();
    window.location.hash = "login-failed";
  }
});

//# sourceMappingURL=/assets/app.js.map
