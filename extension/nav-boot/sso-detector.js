/**
 * 企业 SAML/OAuth/IdP 多跳登录识别（纯静态）。
 * 这类跳转绝不是“非用户手势自动跳转”，拦截策略必须放行。
 */
;(function (NS) {
  "use strict";

  const { PackageClassifier } = NS;

  class SsoDetector {
    /**
     * 企业 SAML/OAuth/IdP 登录多跳，例如 access.broadcom.com/default/saml/v1/idp/login。
     * @param {string|URL} url
     */
    static isAuthSsoRedirectUrl(url) {
      try {
        const u = new URL(PackageClassifier.hrefOf(url), location.href);
        if (!/^https?:$/i.test(u.protocol)) return false;
        const path = (u.pathname || "").toLowerCase();
        const host = (u.hostname || "").toLowerCase();
        const q = u.search || "";
        if (/\.(zip|exe|apk|dmg|msi|rar|7z)(?:\?|#|$)/i.test(path) || PackageClassifier.PKG.test(u.href)) return false;
        // 路径形态：SAML / OAuth / OIDC / CAS / ADFS / IdP
        if (/\/(?:saml2?|sso|oauth2?|oidc|openid(?:-connect)?|adfs|cas|idp)(?:\/|$)/i.test(path)) return true;
        if (/\/default\/saml\//i.test(path) || /\/idp\/(?:sso|login|profile|start)/i.test(path)) return true;
        if (/\/oauth2?\/(?:v\d+\/)?(?:authorize|auth|token|logout)/i.test(path)) return true;
        if (/\/(?:login|signin|sign-in|logon|authenticate)(?:\/|$)/i.test(path)
          && /[?&](?:SAMLRequest|SAMLResponse|RelayState|client_id|response_type|redirect_uri|code_challenge|scope)=/i.test(q)) {
          return true;
        }
        // 常见 IdP 主机形态（access.* / login.* / sso.* / accounts.*）
        if (/(?:^|\.)(?:login|sso|auth|accounts|access|idp|sts|adfs|signin)\./i.test(host)
          && /saml|sso|oauth|openid|authorize|idp|login|auth/i.test(path + q)) {
          return true;
        }
        if (/(?:^|\.)(?:okta\.com|auth0\.com|microsoftonline\.com|windows\.net|google\.com|onelogin\.com|pingidentity\.com|duo\.com|cloudflareaccess\.com)$/i.test(host)) {
          return true;
        }
        return false;
      } catch {
        return false;
      }
    }
  }

  NS.SsoDetector = SsoDetector;
})(window.SilverfoxNavBoot ??= {});
