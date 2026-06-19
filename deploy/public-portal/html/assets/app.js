window.NB_PORTAL_CONFIG = {
  apiBase: "/api/v1",
  invoiceEndpoint: "/api/v1/invoices",
  adminStatusEndpoint: "/admin/status",
  internalStatusEndpoint: "/internal-api/status",
  internalPortalUrl: "http://intranet.internal.local:18080",
  internalGitHost: "git.internal.local",
  internalGitUrl: "git://git.internal.local:19418/infra-deploy.git",
  internalDbHost: "db01.internal.local",
  internalDbEndpoint: "db01.internal.local:13306",
  internalRedisHost: "redis-cache.internal.local",
  internalRedisEndpoint: "redis-cache.internal.local:16379",
  legacyIntegration: {
    INTERNAL_API_KEY: "nb_api_ro_2026_04_status",
    GITEA_TOKEN: "nbg_git_ro_2026_04_legacy",
    BACKUP_READER_PASSWORD: "NbBackupReader-2026-04",
    PORTAL_READER_TOKEN: "nbp_reader_2026_04_window"
  }
};

document.addEventListener("submit", (event) => {
  if (event.target.matches("form[action='/api/v1/login']")) {
    event.preventDefault();
    window.location.hash = "login-failed";
  }
});

//# sourceMappingURL=/assets/app.js.map
