
class AtmosphereClient {
  constructor() {
    this.TopBarTitleElement = document.getElementById("TopBarTitle");
    this.SidebarElement = document.getElementById("SidebarElement");
    this.SidebarCollapseButton = document.getElementById("SidebarCollapseButton");
    this.SidebarOpenButton = document.getElementById("SidebarOpenButton");
    this.SidebarBackdrop = document.getElementById("SidebarBackdrop");

    this.LastSelfScanData = null;
    this.LastLookupData = null;
    this.LastBatchData = null;
    this.ActiveMapInstances = [];
    this.ActiveGlobeInstances = [];

    this.ViewTitleMap = {
      SelfScan: "Self Scan",
      IpLookup: "IP Lookup",
      BatchLookup: "Batch Lookup",
      DnsTools: "DNS Tools",
      SslCheck: "SSL Certificate",
      WhoisLookup: "Whois Lookup",
      HeaderInspect: "Header Inspector",
      NetworkTools: "Network Tools",
      TechDetect: "Tech Stack Detector",
      Subdomains: "Subdomain Finder",
      Blacklist: "Blacklist Check",
      WebRecon: "Web Recon",
      About: "About",
    };

    this.BindSidebarEvents();
    this.BindFormEvents();
    this.InitializeSidebarState();
  }

  InitializeSidebarState() {
    if (window.innerWidth <= 800) {
      this.SidebarElement.classList.add("is-collapsed");
      const CollapseIconElement = this.SidebarCollapseButton.querySelector("i");
      CollapseIconElement.classList.remove("fa-angles-left");
      CollapseIconElement.classList.add("fa-angles-right");
      const OpenIconElement = this.SidebarOpenButton.querySelector("i");
      OpenIconElement.classList.remove("fa-angles-left");
      OpenIconElement.classList.add("fa-angles-right");
    }
  }

  BindSidebarEvents() {
    document.querySelectorAll(".NavItem").forEach((ItemElement) => {
      ItemElement.addEventListener("click", () => this.SwitchView(ItemElement.dataset.view));
    });

    this.SidebarCollapseButton.addEventListener("click", () => this.ToggleSidebarCollapse());
    this.SidebarOpenButton.addEventListener("click", () => this.ToggleSidebarCollapse());
    this.SidebarBackdrop.addEventListener("click", () => this.ToggleSidebarCollapse());
  }

  ToggleSidebarCollapse() {
    this.SidebarElement.classList.toggle("is-collapsed");
    const IsCollapsed = this.SidebarElement.classList.contains("is-collapsed");
    const CollapseIconElement = this.SidebarCollapseButton.querySelector("i");
    CollapseIconElement.classList.toggle("fa-angles-left", !IsCollapsed);
    CollapseIconElement.classList.toggle("fa-angles-right", IsCollapsed);
    const OpenIconElement = this.SidebarOpenButton.querySelector("i");
    OpenIconElement.classList.toggle("fa-angles-right", IsCollapsed);
    OpenIconElement.classList.toggle("fa-angles-left", !IsCollapsed);
    if (window.innerWidth <= 800) {
      this.SidebarBackdrop.classList.toggle("is-visible", !IsCollapsed);
    }
  }

  SwitchView(ViewName) {
    document.querySelectorAll(".NavItem").forEach((ItemElement) => {
      ItemElement.classList.toggle("is-active", ItemElement.dataset.view === ViewName);
    });
    document.querySelectorAll(".ViewPanel").forEach((PanelElement) => {
      PanelElement.classList.toggle("is-active", PanelElement.id === ViewName + "View");
    });
    this.TopBarTitleElement.textContent = this.ViewTitleMap[ViewName] || ViewName;
    requestAnimationFrame(() => {
      this.ActiveMapInstances.forEach((MapInstance) => MapInstance.invalidateSize());
    });
    if (window.innerWidth <= 800) {
      this.SidebarElement.classList.add("is-collapsed");
      this.SidebarBackdrop.classList.remove("is-visible");
      const CollapseIconElement = this.SidebarCollapseButton.querySelector("i");
      CollapseIconElement.classList.remove("fa-angles-left");
      CollapseIconElement.classList.add("fa-angles-right");
      const OpenIconElement = this.SidebarOpenButton.querySelector("i");
      OpenIconElement.classList.remove("fa-angles-left");
      OpenIconElement.classList.add("fa-angles-right");
    }
  }

  BindFormEvents() {
    document.getElementById("LookupForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunLookup(document.getElementById("LookupInput").value.trim());
    });

    document.getElementById("BatchForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      const RawLines = document.getElementById("BatchInput").value.split("\n");
      const CleanedIps = RawLines.map((Line) => Line.trim()).filter(Boolean);
      this.RunBatchLookup(CleanedIps);
    });

    document.getElementById("DnsForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunDnsResolve(document.getElementById("DnsInput").value.trim());
    });

    document.getElementById("ReverseDnsForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunReverseDns(document.getElementById("ReverseDnsInput").value.trim());
    });

    document.getElementById("DnsRecordsForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunDnsRecords(document.getElementById("DnsRecordsInput").value.trim());
    });

    document.getElementById("SslCheckForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunSslCheck(document.getElementById("SslCheckInput").value.trim());
    });

    document.getElementById("WhoisForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunWhoisLookup(document.getElementById("WhoisInput").value.trim());
    });

    document.getElementById("HeaderInspectForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunHeaderInspect(document.getElementById("HeaderInspectInput").value.trim());
    });

    document.getElementById("PortCheckForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunPortCheck(document.getElementById("PortCheckInput").value.trim());
    });

    document.getElementById("PingForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunPing(document.getElementById("PingInput").value.trim());
    });

    document.getElementById("TechDetectForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunTechDetect(document.getElementById("TechDetectInput").value.trim());
    });

    document.getElementById("SubdomainForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunSubdomainEnum(document.getElementById("SubdomainInput").value.trim());
    });

    document.getElementById("BlacklistForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunBlacklistCheck(document.getElementById("BlacklistInput").value.trim());
    });

    document.getElementById("PreviewForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunPreview(document.getElementById("PreviewInput").value.trim());
    });

    document.getElementById("FaviconForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunFaviconLookup(document.getElementById("FaviconInput").value.trim());
    });

    document.getElementById("RedirectTraceForm").addEventListener("submit", (SubmitEvent) => {
      SubmitEvent.preventDefault();
      this.RunRedirectTrace(document.getElementById("RedirectTraceInput").value.trim());
    });
  }

  async RunSelfScan() {
    const LoadingElement = document.getElementById("SelfScanLoading");
    const ContentElement = document.getElementById("SelfScanContent");

    LoadingElement.style.display = "flex";
    ContentElement.style.display = "none";

    const ClientHintPayload = await this.CollectClientHints();

    try {
      const Response = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ClientHintPayload),
      });

      if (!Response.ok) {
        throw new Error("Request failed with status " + Response.status);
      }

      const ReportData = await Response.json();
      this.LastSelfScanData = ReportData;
      this.RenderSelfScanReport(ReportData, ClientHintPayload);
    } catch (ScanError) {
      console.error("AtmosphereClient scan error:", ScanError);
    } finally {
      LoadingElement.style.display = "none";
      ContentElement.style.display = "block";
    }
  }

  async RunLookup(TargetIp) {
    if (!TargetIp) {
      return;
    }

    const LoadingElement = document.getElementById("LookupLoading");
    const ErrorElement = document.getElementById("LookupError");
    const ContentElement = document.getElementById("LookupContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetIp: TargetIp }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Lookup failed");
      }

      this.LastLookupData = ResultData;
      this.RenderLookupReport(ResultData, ContentElement, "LastLookupData");
    } catch (LookupError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${LookupError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunBatchLookup(TargetIps) {
    if (!TargetIps.length) {
      return;
    }

    const LoadingElement = document.getElementById("BatchLoading");
    const ErrorElement = document.getElementById("BatchError");
    const ContentElement = document.getElementById("BatchContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/batch-lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetIps: TargetIps }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Batch lookup failed");
      }

      this.LastBatchData = ResultData;
      this.RenderBatchReport(ResultData, ContentElement);
    } catch (BatchError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${BatchError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunDnsResolve(TargetHost) {
    if (!TargetHost) {
      return;
    }

    const LoadingElement = document.getElementById("DnsLoading");
    const ErrorElement = document.getElementById("DnsError");
    const ContentElement = document.getElementById("DnsContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/dns-resolve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetHost: TargetHost }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "DNS resolution failed");
      }

      const IpListHtml = ResultData.ResolvedIps.map((IpAddress) => `<span class="Badge Badge-Blue">${IpAddress}</span>`).join(" ");
      ContentElement.innerHTML = `
        <table class="DataTable">
          <tr><td>Hostname</td><td>${ResultData.Hostname}</td></tr>
          <tr><td>Resolved IPs</td><td>${IpListHtml}</td></tr>
        </table>
      `;
    } catch (DnsError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${DnsError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunReverseDns(TargetIp) {
    if (!TargetIp) {
      return;
    }

    const LoadingElement = document.getElementById("ReverseDnsLoading");
    const ErrorElement = document.getElementById("ReverseDnsError");
    const ContentElement = document.getElementById("ReverseDnsContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/reverse-dns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetIp: TargetIp }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Reverse DNS lookup failed");
      }

      const HostnameListHtml = ResultData.Hostnames.map((Hostname) => `<span class="Badge Badge-Green">${Hostname}</span>`).join(" ");
      ContentElement.innerHTML = `
        <table class="DataTable">
          <tr><td>IP Address</td><td>${ResultData.Ip}</td></tr>
          <tr><td>PTR Records</td><td>${HostnameListHtml}</td></tr>
        </table>
      `;
    } catch (ReverseDnsError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${ReverseDnsError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunDnsRecords(TargetHost) {
    if (!TargetHost) {
      return;
    }

    const LoadingElement = document.getElementById("DnsRecordsLoading");
    const ErrorElement = document.getElementById("DnsRecordsError");
    const ContentElement = document.getElementById("DnsRecordsContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/dns-records", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetHost: TargetHost }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "DNS records lookup failed");
      }

      this.RenderDnsRecordsReport(ResultData, ContentElement);
    } catch (RecordsError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${RecordsError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  RenderDnsRecordsReport(ResultData, ContentElement) {
    const BuildBadgeList = (Entries, ColorName) =>
      (Entries && Entries.length > 0)
        ? Entries.map((Entry) => `<span class="Badge Badge-${ColorName}">${Entry}</span>`).join(" ")
        : "None Found";

    ContentElement.innerHTML = `
      <table class="DataTable">
        <tr><td>Hostname</td><td>${ResultData.Hostname}</td></tr>
        <tr><td>A Records</td><td>${BuildBadgeList(ResultData.ARecords, "Blue")}</td></tr>
        <tr><td>AAAA Records</td><td>${BuildBadgeList(ResultData.AaaaRecords, "Purple")}</td></tr>
        <tr><td>MX Records</td><td>${BuildBadgeList(ResultData.MxRecords, "Orange")}</td></tr>
        <tr><td>TXT Records</td><td>${BuildBadgeList(ResultData.TxtRecords, "Green")}</td></tr>
        <tr><td>NS Records</td><td>${BuildBadgeList(ResultData.NsRecords, "Blue")}</td></tr>
        <tr><td>CNAME Record</td><td>${ResultData.CnameRecord || "None Found"}</td></tr>
      </table>
    `;
  }

  async RunSslCheck(TargetHost) {
    if (!TargetHost) {
      return;
    }

    const LoadingElement = document.getElementById("SslCheckLoading");
    const ErrorElement = document.getElementById("SslCheckError");
    const ContentElement = document.getElementById("SslCheckContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/ssl-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetHost: TargetHost }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "SSL certificate check failed");
      }

      this.RenderSslCheckReport(ResultData, ContentElement);
    } catch (SslError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${SslError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  RenderSslCheckReport(ResultData, ContentElement) {
    const Certificate = ResultData.Certificate;
    const ExpiryBadge = Certificate.IsExpired
      ? this.WrapBadge("Expired", "Red")
      : (Certificate.DaysUntilExpiry <= 14 ? this.WrapBadge(`${Certificate.DaysUntilExpiry} Days Left`, "Orange") : this.WrapBadge(`${Certificate.DaysUntilExpiry} Days Left`, "Green"));

    const ChainRowsHtml = ResultData.ChainInfo.map((ChainCertificate, ChainIndex) => `
      <tr><td>Chain Certificate ${ChainIndex + 1}</td><td>${ChainCertificate.Subject || "Unknown"} &middot; Issued By ${ChainCertificate.Issuer || "Unknown"}</td></tr>
    `).join("");

    ContentElement.innerHTML = `
      <div class="ResultHeader">
        <span class="ResultHeader-Ip">${ResultData.Hostname}</span>
        <span class="ResultHeader-Location">${Certificate.Subject || "Unknown Subject"}</span>
      </div>

      <div class="SectionLabel"><i class="fa-solid fa-certificate"></i> Certificate Details</div>
      <table class="DataTable">
        <tr><td>Subject</td><td>${Certificate.Subject || "Unknown"}</td></tr>
        <tr><td>Issuer</td><td>${Certificate.Issuer || "Unknown"}</td></tr>
        <tr><td>Serial Number</td><td>${Certificate.SerialNumber || "Unknown"}</td></tr>
        <tr><td>Signature Algorithm</td><td>${Certificate.SignatureAlgorithm || "Unknown"}</td></tr>
        <tr><td>Valid From</td><td>${Certificate.NotBefore || "Unknown"}</td></tr>
        <tr><td>Valid Until</td><td>${Certificate.NotAfter || "Unknown"}</td></tr>
        <tr><td>Expiry Status</td><td>${ExpiryBadge}</td></tr>
        <tr><td>Self Signed</td><td>${Certificate.IsSelfSigned ? this.WrapBadge("Yes", "Orange") : this.WrapBadge("No", "Green")}</td></tr>
        <tr><td>TLS Version</td><td>${Certificate.TlsVersion || "Unknown"}</td></tr>
        <tr><td>Cipher Suite</td><td>${Certificate.CipherSuite || "Unknown"}</td></tr>
        <tr><td>DNS Names</td><td>${(Certificate.DnsNames || []).join(", ") || "None Listed"}</td></tr>
      </table>

      <div class="SectionLabel"><i class="fa-solid fa-link"></i> Certificate Chain (${ResultData.ChainLength})</div>
      <table class="DataTable">
        ${ChainRowsHtml}
      </table>
    `;
  }

  async RunWhoisLookup(TargetDomain) {
    if (!TargetDomain) {
      return;
    }

    const LoadingElement = document.getElementById("WhoisLoading");
    const ErrorElement = document.getElementById("WhoisError");
    const ContentElement = document.getElementById("WhoisContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/whois", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetDomain: TargetDomain }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Whois lookup failed");
      }

      ContentElement.innerHTML = `
        <div class="ResultHeader">
          <span class="ResultHeader-Ip">${ResultData.Domain}</span>
          <span class="ResultHeader-Location">Queried ${ResultData.WhoisHost}</span>
        </div>
        <div class="SectionLabel"><i class="fa-solid fa-file-lines"></i> Raw Whois Record</div>
        <pre class="WhoisRecord">${this.EscapeHtml(ResultData.RawRecord)}</pre>
      `;
    } catch (WhoisError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${WhoisError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunHeaderInspect(TargetUrl) {
    if (!TargetUrl) {
      return;
    }

    const LoadingElement = document.getElementById("HeaderInspectLoading");
    const ErrorElement = document.getElementById("HeaderInspectError");
    const ContentElement = document.getElementById("HeaderInspectContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/header-inspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetUrl: TargetUrl }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Header inspection failed");
      }

      this.RenderHeaderInspectReport(ResultData, ContentElement);
    } catch (InspectError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${InspectError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  RenderHeaderInspectReport(ResultData, ContentElement) {
    const Flags = ResultData.SecurityFlags;
    const HeaderRowsHtml = (ResultData.Headers || [])
      .sort((FirstHeader, SecondHeader) => FirstHeader.Name.localeCompare(SecondHeader.Name))
      .map((HeaderEntry) => `<tr><td>${HeaderEntry.Name}</td><td>${HeaderEntry.Value}</td></tr>`)
      .join("");

    ContentElement.innerHTML = `
      <div class="ResultHeader">
        <span class="ResultHeader-Ip">${ResultData.StatusCode}</span>
        <span class="ResultHeader-Location">${ResultData.StatusText}</span>
      </div>

      <div class="SectionLabel"><i class="fa-solid fa-gauge-high"></i> Response Summary</div>
      <table class="DataTable">
        <tr><td>Requested URL</td><td>${ResultData.Url}</td></tr>
        <tr><td>Final URL</td><td>${ResultData.FinalUrl}</td></tr>
        <tr><td>Response Time</td><td>${ResultData.ResponseTimeMs} ms</td></tr>
      </table>

      <div class="SectionLabel"><i class="fa-solid fa-shield-halved"></i> Security Headers</div>
      <table class="DataTable">
        <tr><td>Strict-Transport-Security</td><td>${Flags.HasHsts ? this.WrapBadge("Present", "Green") : this.WrapBadge("Missing", "Red")}</td></tr>
        <tr><td>Content-Security-Policy</td><td>${Flags.HasCsp ? this.WrapBadge("Present", "Green") : this.WrapBadge("Missing", "Red")}</td></tr>
        <tr><td>X-Frame-Options</td><td>${Flags.HasXFrameOptions ? this.WrapBadge("Present", "Green") : this.WrapBadge("Missing", "Red")}</td></tr>
        <tr><td>X-Content-Type-Options</td><td>${Flags.HasXContentTypeOpts ? this.WrapBadge("Present", "Green") : this.WrapBadge("Missing", "Red")}</td></tr>
        <tr><td>Referrer-Policy</td><td>${Flags.HasReferrerPolicy ? this.WrapBadge("Present", "Green") : this.WrapBadge("Missing", "Red")}</td></tr>
      </table>

      <div class="SectionLabel"><i class="fa-solid fa-list"></i> All Response Headers</div>
      <table class="DataTable">
        ${HeaderRowsHtml}
      </table>
    `;
  }

  async RunPortCheck(TargetHost) {
    if (!TargetHost) {
      return;
    }

    const LoadingElement = document.getElementById("PortCheckLoading");
    const ErrorElement = document.getElementById("PortCheckError");
    const ContentElement = document.getElementById("PortCheckContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/port-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetHost: TargetHost }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Port scan failed");
      }

      const PortRowsHtml = ResultData.Ports.map((PortEntry) => `
        <tr>
          <td>${PortEntry.ServiceName} (${PortEntry.Port})</td>
          <td>${PortEntry.IsOpen ? this.WrapBadge("Open", "Green") : this.WrapBadge("Closed", "Red")} <span class="Badge Badge-Blue">${PortEntry.LatencyMs} ms</span></td>
        </tr>
      `).join("");

      ContentElement.innerHTML = `
        <table class="DataTable">
          <tr><td>Hostname</td><td>${ResultData.Hostname}</td></tr>
        </table>
        <div class="SectionLabel"><i class="fa-solid fa-ethernet"></i> Port Results</div>
        <table class="DataTable">
          ${PortRowsHtml}
        </table>
      `;
    } catch (PortError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${PortError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunPing(TargetHost) {
    if (!TargetHost) {
      return;
    }

    const LoadingElement = document.getElementById("PingLoading");
    const ErrorElement = document.getElementById("PingError");
    const ContentElement = document.getElementById("PingContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/ping", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetHost: TargetHost }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Ping failed");
      }

      const AttemptRowsHtml = ResultData.Attempts.map((Attempt) => `
        <tr>
          <td>Attempt ${Attempt.Sequence}</td>
          <td>${Attempt.Success ? this.WrapBadge(`${Attempt.LatencyMs} ms`, "Green") : this.WrapBadge("Timed Out", "Red")}</td>
        </tr>
      `).join("");

      ContentElement.innerHTML = `
        <table class="DataTable">
          <tr><td>Hostname</td><td>${ResultData.Hostname}</td></tr>
          <tr><td>Resolved IP</td><td>${ResultData.ResolvedIp}</td></tr>
          <tr><td>Min Latency</td><td>${ResultData.MinLatencyMs} ms</td></tr>
          <tr><td>Max Latency</td><td>${ResultData.MaxLatencyMs} ms</td></tr>
          <tr><td>Avg Latency</td><td>${ResultData.AvgLatencyMs} ms</td></tr>
          <tr><td>Packet Loss</td><td>${ResultData.PacketLoss.toFixed(1)}%</td></tr>
        </table>
        <div class="SectionLabel"><i class="fa-solid fa-signal"></i> Attempts</div>
        <table class="DataTable">
          ${AttemptRowsHtml}
        </table>
      `;
    } catch (PingError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${PingError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  EscapeHtml(RawText) {
    const EscapeElement = document.createElement("div");
    EscapeElement.textContent = RawText || "";
    return EscapeElement.innerHTML;
  }

  async RunTechDetect(TargetUrl) {
    if (!TargetUrl) {
      return;
    }

    const LoadingElement = document.getElementById("TechDetectLoading");
    const ErrorElement = document.getElementById("TechDetectError");
    const ContentElement = document.getElementById("TechDetectContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/tech-detect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetUrl: TargetUrl }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Tech detection failed");
      }

      const GroupedByCategory = {};
      (ResultData.DetectedEntries || []).forEach((Entry) => {
        if (!GroupedByCategory[Entry.Category]) {
          GroupedByCategory[Entry.Category] = [];
        }
        GroupedByCategory[Entry.Category].push(Entry.Name);
      });

      const CategoryRowsHtml = Object.keys(GroupedByCategory).sort().map((CategoryName) => `
        <tr>
          <td>${CategoryName}</td>
          <td>${GroupedByCategory[CategoryName].map((Name) => this.WrapBadge(Name, "Blue")).join(" ")}</td>
        </tr>
      `).join("") || `<tr><td colspan="2">No known technology signatures detected</td></tr>`;

      ContentElement.innerHTML = `
        <div class="ResultHeader">
          <span class="ResultHeader-Ip">${ResultData.Url}</span>
          <span class="ResultHeader-Location">${(ResultData.DetectedEntries || []).length} Signatures Found</span>
        </div>

        <div class="SectionLabel"><i class="fa-solid fa-layer-group"></i> Detected Technologies</div>
        <table class="DataTable">
          ${CategoryRowsHtml}
        </table>

        <div class="SectionLabel"><i class="fa-solid fa-server"></i> Server Headers</div>
        <table class="DataTable">
          <tr><td>Server</td><td>${ResultData.ServerHeader || "Not Disclosed"}</td></tr>
          <tr><td>X-Powered-By</td><td>${ResultData.PoweredByHeader || "Not Disclosed"}</td></tr>
        </table>
      `;
    } catch (TechError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${TechError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunSubdomainEnum(TargetDomain) {
    if (!TargetDomain) {
      return;
    }

    const LoadingElement = document.getElementById("SubdomainLoading");
    const ErrorElement = document.getElementById("SubdomainError");
    const ContentElement = document.getElementById("SubdomainContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/subdomain-enum", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetDomain: TargetDomain }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Subdomain enumeration failed");
      }

      const SubdomainRowsHtml = (ResultData.Subdomains || []).map((SubdomainName) => `
        <tr><td colspan="2">${SubdomainName}</td></tr>
      `).join("") || `<tr><td colspan="2">No subdomains discovered</td></tr>`;

      ContentElement.innerHTML = `
        <div class="ResultHeader">
          <span class="ResultHeader-Ip">${ResultData.Domain}</span>
          <span class="ResultHeader-Location">${ResultData.TotalDiscovered} Subdomains Found</span>
        </div>
        <div class="SectionLabel"><i class="fa-solid fa-sitemap"></i> Discovered Subdomains</div>
        <table class="DataTable">
          ${SubdomainRowsHtml}
        </table>
      `;
    } catch (SubdomainError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${SubdomainError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunBlacklistCheck(TargetIp) {
    if (!TargetIp) {
      return;
    }

    const LoadingElement = document.getElementById("BlacklistLoading");
    const ErrorElement = document.getElementById("BlacklistError");
    const ContentElement = document.getElementById("BlacklistContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/blacklist-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetIp: TargetIp }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Blacklist check failed");
      }

      const ZoneRowsHtml = (ResultData.Entries || []).map((Entry) => `
        <tr>
          <td>${Entry.ZoneName}</td>
          <td>${Entry.IsListed ? this.WrapBadge("Listed", "Red") : this.WrapBadge("Clean", "Green")}</td>
        </tr>
      `).join("");

      const OverallBadge = ResultData.ListedCount > 0
        ? this.WrapBadge(`Listed On ${ResultData.ListedCount} Of ${ResultData.TotalChecked}`, "Red")
        : this.WrapBadge(`Clean On All ${ResultData.TotalChecked} Zones`, "Green");

      ContentElement.innerHTML = `
        <div class="ResultHeader">
          <span class="ResultHeader-Ip">${ResultData.Ip}</span>
          <span class="ResultHeader-Location">${OverallBadge}</span>
        </div>
        <div class="SectionLabel"><i class="fa-solid fa-ban"></i> DNSBL Zone Results</div>
        <table class="DataTable">
          ${ZoneRowsHtml}
        </table>
      `;
    } catch (BlacklistError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${BlacklistError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunPreview(TargetUrl) {
    if (!TargetUrl) {
      return;
    }

    const LoadingElement = document.getElementById("PreviewLoading");
    const ErrorElement = document.getElementById("PreviewError");
    const ContentElement = document.getElementById("PreviewContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetUrl: TargetUrl }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Preview fetch failed");
      }

      const PreviewImageHtml = ResultData.PreviewImageUrl
        ? `<img src="${ResultData.PreviewImageUrl}" alt="Preview" class="PreviewImage">`
        : `<div class="PreviewImagePlaceholder"><i class="fa-solid fa-image"></i> No Preview Image Found</div>`;

      ContentElement.innerHTML = `
        ${PreviewImageHtml}
        <table class="DataTable">
          <tr><td>URL</td><td>${ResultData.Url}</td></tr>
          <tr><td>Page Title</td><td>${ResultData.PageTitle || "Not Found"}</td></tr>
          <tr><td>OG Title</td><td>${ResultData.OgTitle || "Not Found"}</td></tr>
          <tr><td>Site Name</td><td>${ResultData.OgSiteName || "Not Found"}</td></tr>
          <tr><td>Description</td><td>${ResultData.Description || "Not Found"}</td></tr>
          <tr><td>Theme Color</td><td>${ResultData.ThemeColor || "Not Set"}</td></tr>
        </table>
      `;
    } catch (PreviewError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${PreviewError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunFaviconLookup(TargetUrl) {
    if (!TargetUrl) {
      return;
    }

    const LoadingElement = document.getElementById("FaviconLoading");
    const ErrorElement = document.getElementById("FaviconError");
    const ContentElement = document.getElementById("FaviconContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/favicon-lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetUrl: TargetUrl }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Favicon lookup failed");
      }

      ContentElement.innerHTML = `
        <div class="ResultHeader">
          <img src="${ResultData.FaviconUrl}" alt="Favicon" class="FaviconThumbnail">
          <span class="ResultHeader-Location">${ResultData.SizeBytes} Bytes</span>
        </div>
        <table class="DataTable">
          <tr><td>Favicon URL</td><td>${ResultData.FaviconUrl}</td></tr>
          <tr><td>MD5 Hash</td><td>${ResultData.Md5Hash}</td></tr>
          <tr><td>MurmurHash3 (Shodan)</td><td>${ResultData.Mmh3Hash}</td></tr>
          <tr><td>Shodan Query</td><td><a href="${ResultData.ShodanQueryUrl}" target="_blank" class="InlineLink">${ResultData.ShodanQueryUrl}</a></td></tr>
        </table>
      `;
    } catch (FaviconError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${FaviconError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async RunRedirectTrace(TargetUrl) {
    if (!TargetUrl) {
      return;
    }

    const LoadingElement = document.getElementById("RedirectTraceLoading");
    const ErrorElement = document.getElementById("RedirectTraceError");
    const ContentElement = document.getElementById("RedirectTraceContent");

    ErrorElement.style.display = "none";
    ContentElement.innerHTML = "";
    LoadingElement.style.display = "flex";

    try {
      const Response = await fetch("/api/redirect-trace", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ TargetUrl: TargetUrl }),
      });

      const ResultData = await Response.json();

      if (!Response.ok) {
        throw new Error(ResultData.Error || "Redirect trace failed");
      }

      const HopRowsHtml = (ResultData.Hops || []).map((Hop) => `
        <tr>
          <td>Hop ${Hop.HopNumber}</td>
          <td>${this.WrapBadge(Hop.StatusCode, Hop.StatusCode >= 400 ? "Red" : (Hop.StatusCode >= 300 ? "Orange" : "Green"))} ${Hop.Url}</td>
        </tr>
      `).join("");

      ContentElement.innerHTML = `
        <div class="ResultHeader">
          <span class="ResultHeader-Ip">${ResultData.TotalHops} Hops</span>
          <span class="ResultHeader-Location">${ResultData.FinalUrl}</span>
        </div>
        <div class="SectionLabel"><i class="fa-solid fa-arrows-turn-right"></i> Redirect Chain</div>
        <table class="DataTable">
          ${HopRowsHtml}
        </table>
      `;
    } catch (RedirectError) {
      ErrorElement.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${RedirectError.message}`;
      ErrorElement.style.display = "flex";
    } finally {
      LoadingElement.style.display = "none";
    }
  }

  async CollectClientHints() {
    const LanguageList = navigator.languages ? Array.from(navigator.languages) : [navigator.language];

    let ConnectionType = "Unknown";
    if (navigator.connection && navigator.connection.effectiveType) {
      ConnectionType = navigator.connection.effectiveType;
    }

    return {
      LocalIps: await this.DiscoverLocalIps(),
      ScreenWidth: window.screen.width,
      ScreenHeight: window.screen.height,
      ColorDepth: window.screen.colorDepth,
      PixelRatio: window.devicePixelRatio || 1,
      HardwareThreads: navigator.hardwareConcurrency || 0,
      DeviceMemory: navigator.deviceMemory || 0,
      TimezoneName: Intl.DateTimeFormat().resolvedOptions().timeZone,
      LanguageList: LanguageList,
      PlatformName: navigator.platform || "Unknown",
      TouchSupport: "ontouchstart" in window || navigator.maxTouchPoints > 0,
      CookieEnabled: navigator.cookieEnabled,
      DoNotTrack: navigator.doNotTrack || "Unspecified",
      ConnectionType: ConnectionType,
    };
  }

  DiscoverLocalIps() {
    return new Promise((Resolve) => {
      const DiscoveredIps = new Set();
      const PeerConnectionClass = window.RTCPeerConnection || window.webkitRTCPeerConnection;

      if (!PeerConnectionClass) {
        Resolve([]);
        return;
      }

      const Connection = new PeerConnectionClass({ iceServers: [] });
      Connection.createDataChannel("");

      Connection.onicecandidate = (Event) => {
        if (!Event || !Event.candidate) {
          Connection.close();
          Resolve(Array.from(DiscoveredIps));
          return;
        }
        const CandidateMatch = Event.candidate.candidate.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/);
        if (CandidateMatch) {
          DiscoveredIps.add(CandidateMatch[1]);
        }
      };

      Connection.createOffer()
        .then((OfferDescription) => Connection.setLocalDescription(OfferDescription))
        .catch(() => Resolve([]));

      setTimeout(() => {
        Resolve(Array.from(DiscoveredIps));
      }, 1200);
    });
  }

  BuildDataRow(KeyLabel, ValueContent) {
    return `<tr><td>${KeyLabel}</td><td>${ValueContent}</td></tr>`;
  }

  ResolveDeviceBadge(DeviceType) {
    const BadgeColorMap = {
      Desktop: "Blue",
      Mobile: "Green",
      Tablet: "Orange",
      Bot: "Red",
    };
    const ColorName = BadgeColorMap[DeviceType] || "Blue";
    return this.WrapBadge(DeviceType || "Unknown", ColorName);
  }

  WrapBadge(LabelText, ColorName) {
    return `<span class="Badge Badge-${ColorName}">${LabelText}</span>`;
  }

  BuildMapSectionHtml(GeoData) {
    if (!GeoData.Latitude && !GeoData.Longitude) {
      return "";
    }

    const MapContainerId = `MapCanvas-${Math.random().toString(36).slice(2)}`;
    const GlobeContainerId = `GlobeCanvas-${Math.random().toString(36).slice(2)}`;

    return `
      <div class="SectionLabel MapSectionLabel">
        <span><i class="fa-solid fa-map-location-dot"></i> Location Map</span>
        <div class="MapViewToggle" data-map-target="${MapContainerId}" data-globe-target="${GlobeContainerId}">
          <button type="button" class="MapViewToggle-Btn is-active" data-mode="2d">2D Map</button>
          <button type="button" class="MapViewToggle-Btn" data-mode="3d">3D Globe</button>
        </div>
      </div>
      <div class="MapEmbed" id="${MapContainerId}" data-lat="${GeoData.Latitude}" data-lon="${GeoData.Longitude}" data-label="${GeoData.City || ""}, ${GeoData.Country || ""}"></div>
      <div class="GlobeEmbed" id="${GlobeContainerId}" data-lat="${GeoData.Latitude}" data-lon="${GeoData.Longitude}" data-label="${GeoData.City || ""}, ${GeoData.Country || ""}" style="display: none;"></div>
      <div class="MapLinkRow">
        <a class="MapLink" href="${GeoData.GoogleMapUrl}" target="_blank"><i class="fa-brands fa-google"></i> Open in Google Maps</a>
        <a class="MapLink" href="${GeoData.OsmMapUrl}" target="_blank"><i class="fa-solid fa-map"></i> Open in OpenStreetMap</a>
      </div>
    `;
  }

  InitializeSatelliteMaps(ContainerElement) {
    const MapCanvasList = ContainerElement.querySelectorAll(".MapEmbed[data-lat]");
    MapCanvasList.forEach((CanvasElement) => {
      const Latitude = parseFloat(CanvasElement.dataset.lat);
      const Longitude = parseFloat(CanvasElement.dataset.lon);
      const LabelText = CanvasElement.dataset.label || "";

      const MapInstance = window.L.map(CanvasElement.id, {
        zoomControl: true,
        attributionControl: true,
      }).setView([Latitude, Longitude], 11);

      window.L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}", {
        maxZoom: 18,
        attribution: "Tiles &copy; Esri",
      }).addTo(MapInstance);

      window.L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}", {
        maxZoom: 18,
      }).addTo(MapInstance);

      window.L.marker([Latitude, Longitude]).addTo(MapInstance).bindPopup(LabelText);

      this.ActiveMapInstances.push(MapInstance);

      requestAnimationFrame(() => {
        MapInstance.invalidateSize();
        setTimeout(() => MapInstance.invalidateSize(), 250);
      });
    });

    ContainerElement.querySelectorAll(".MapViewToggle").forEach((ToggleElement) => {
      ToggleElement.querySelectorAll(".MapViewToggle-Btn").forEach((ButtonElement) => {
        ButtonElement.addEventListener("click", () => {
          const SelectedMode = ButtonElement.dataset.mode;
          const MapTargetElement = document.getElementById(ToggleElement.dataset.mapTarget);
          const GlobeTargetElement = document.getElementById(ToggleElement.dataset.globeTarget);

          ToggleElement.querySelectorAll(".MapViewToggle-Btn").forEach((SiblingButton) => {
            SiblingButton.classList.toggle("is-active", SiblingButton === ButtonElement);
          });

          if (SelectedMode === "3d") {
            MapTargetElement.style.display = "none";
            GlobeTargetElement.style.display = "flex";
            if (GlobeTargetElement.dataset.initialized !== "true") {
              GlobeTargetElement.innerHTML = `<div class="GlobeEmbed-Error"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading globe...</div>`;
            }
            this.InitializeGlobe(GlobeTargetElement);
          } else {
            GlobeTargetElement.style.display = "none";
            MapTargetElement.style.display = "block";
            const MatchingMapInstance = this.ActiveMapInstances.find((Instance) => Instance._container && Instance._container.id === MapTargetElement.id);
            if (MatchingMapInstance) {
              requestAnimationFrame(() => MatchingMapInstance.invalidateSize());
            }
          }
        });
      });
    });
  }

  async InitializeGlobe(GlobeContainerElement) {
    if (GlobeContainerElement.dataset.initialized === "true") {
      return;
    }
    if (!window.THREE) {
      GlobeContainerElement.innerHTML = `<div class="GlobeEmbed-Error"><i class="fa-solid fa-triangle-exclamation"></i> 3D engine failed to load</div>`;
      return;
    }
    GlobeContainerElement.dataset.initialized = "true";
    GlobeContainerElement.innerHTML = "";

    const Latitude = parseFloat(GlobeContainerElement.dataset.lat);
    const Longitude = parseFloat(GlobeContainerElement.dataset.lon);
    const ContainerWidth = GlobeContainerElement.clientWidth || 320;
    const ContainerHeight = GlobeContainerElement.clientHeight || 320;

    const Scene = new window.THREE.Scene();
    const Camera = new window.THREE.PerspectiveCamera(45, ContainerWidth / ContainerHeight, 0.1, 1000);
    Camera.position.z = 2.6;

    const Renderer = new window.THREE.WebGLRenderer({ antialias: true, alpha: true });
    Renderer.setSize(ContainerWidth, ContainerHeight);
    Renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    GlobeContainerElement.appendChild(Renderer.domElement);

    const GlobeGroup = new window.THREE.Group();
    Scene.add(GlobeGroup);

    const SphereGeometry = new window.THREE.SphereGeometry(1, 48, 48);
    const SphereMaterial = new window.THREE.MeshBasicMaterial({
      color: 0x000000,
    });
    const SphereMesh = new window.THREE.Mesh(SphereGeometry, SphereMaterial);
    GlobeGroup.add(SphereMesh);

    const ContinentOutlines = await this.BuildContinentOutlines();
    GlobeGroup.add(ContinentOutlines);

    const GlowGeometry = new window.THREE.SphereGeometry(1.12, 32, 32);
    const GlowMaterial = new window.THREE.MeshBasicMaterial({
      color: 0xbfff4d,
      transparent: true,
      opacity: 0.05,
      side: window.THREE.BackSide,
    });
    const GlowMesh = new window.THREE.Mesh(GlowGeometry, GlowMaterial);
    Scene.add(GlowMesh);

    const StarGeometry = new window.THREE.BufferGeometry();
    const StarCount = 400;
    const StarPositions = new Float32Array(StarCount * 3);
    for (let StarIndex = 0; StarIndex < StarCount; StarIndex++) {
      const Radius = 8 + Math.random() * 6;
      const Theta = Math.random() * Math.PI * 2;
      const Phi = Math.acos(2 * Math.random() - 1);
      StarPositions[StarIndex * 3] = Radius * Math.sin(Phi) * Math.cos(Theta);
      StarPositions[StarIndex * 3 + 1] = Radius * Math.sin(Phi) * Math.sin(Theta);
      StarPositions[StarIndex * 3 + 2] = Radius * Math.cos(Phi);
    }
    StarGeometry.setAttribute("position", new window.THREE.BufferAttribute(StarPositions, 3));
    const StarMaterial = new window.THREE.PointsMaterial({ color: 0xffffff, size: 0.02, transparent: true, opacity: 0.6 });
    const StarField = new window.THREE.Points(StarGeometry, StarMaterial);
    Scene.add(StarField);

    const MarkerPosition = this.ConvertLatLonToVector3(Latitude, Longitude, 1.02);
    const MarkerGeometry = new window.THREE.SphereGeometry(0.02, 16, 16);
    const MarkerMaterial = new window.THREE.MeshBasicMaterial({ color: 0xf85149 });
    const MarkerMesh = new window.THREE.Mesh(MarkerGeometry, MarkerMaterial);
    MarkerMesh.position.copy(MarkerPosition);
    GlobeGroup.add(MarkerMesh);

    const PulseGeometry = new window.THREE.SphereGeometry(0.02, 16, 16);
    const PulseMaterial = new window.THREE.MeshBasicMaterial({ color: 0xf85149, transparent: true, opacity: 0.5 });
    const PulseMesh = new window.THREE.Mesh(PulseGeometry, PulseMaterial);
    PulseMesh.position.copy(MarkerPosition);
    GlobeGroup.add(PulseMesh);

    const LabelText = GlobeContainerElement.dataset.label || "";
    const CoordinateText = `${Latitude.toFixed(4)}, ${Longitude.toFixed(4)}`;
    const LabelElement = document.createElement("div");
    LabelElement.className = "GlobeMarkerLabel";
    LabelElement.innerHTML = `<span class="GlobeMarkerLabel-Name">${LabelText}</span><span class="GlobeMarkerLabel-Coords">${CoordinateText}</span>`;
    GlobeContainerElement.appendChild(LabelElement);

    const InitialRotationY = -window.THREE.MathUtils.degToRad(Longitude) - Math.PI / 2;
    const InitialRotationX = window.THREE.MathUtils.degToRad(Latitude) * 0.4;
    GlobeGroup.rotation.y = InitialRotationY;
    GlobeGroup.rotation.x = InitialRotationX;

    let IsDragging = false;
    let PreviousPointerX = 0;
    let PreviousPointerY = 0;
    let AutoRotate = true;

    const StartDrag = (PointerX, PointerY) => {
      IsDragging = true;
      AutoRotate = false;
      PreviousPointerX = PointerX;
      PreviousPointerY = PointerY;
    };
    const MoveDrag = (PointerX, PointerY) => {
      if (!IsDragging) {
        return;
      }
      const DeltaX = PointerX - PreviousPointerX;
      const DeltaY = PointerY - PreviousPointerY;
      GlobeGroup.rotation.y += DeltaX * 0.005;
      GlobeGroup.rotation.x += DeltaY * 0.005;
      PreviousPointerX = PointerX;
      PreviousPointerY = PointerY;
    };
    const EndDrag = () => {
      IsDragging = false;
    };

    Renderer.domElement.addEventListener("mousedown", (Event) => StartDrag(Event.clientX, Event.clientY));
    window.addEventListener("mousemove", (Event) => MoveDrag(Event.clientX, Event.clientY));
    window.addEventListener("mouseup", EndDrag);
    Renderer.domElement.addEventListener("touchstart", (Event) => {
      const Touch = Event.touches[0];
      StartDrag(Touch.clientX, Touch.clientY);
    }, { passive: true });
    Renderer.domElement.addEventListener("touchmove", (Event) => {
      const Touch = Event.touches[0];
      MoveDrag(Touch.clientX, Touch.clientY);
    }, { passive: true });
    Renderer.domElement.addEventListener("touchend", EndDrag);

    let PulseScale = 1;
    let PulseGrowing = true;
    let AnimationFrameHandle = null;

    const AnimateFrame = () => {
      if (AutoRotate) {
        GlobeGroup.rotation.y += 0.0015;
      }

      PulseScale += PulseGrowing ? 0.02 : -0.02;
      if (PulseScale > 2.2) {
        PulseGrowing = false;
      } else if (PulseScale < 1) {
        PulseGrowing = true;
      }
      PulseMesh.scale.set(PulseScale, PulseScale, PulseScale);
      PulseMaterial.opacity = Math.max(0, 0.5 - (PulseScale - 1) * 0.35);

      StarField.rotation.y += 0.0002;

      const ProjectedPosition = MarkerPosition.clone().applyMatrix4(GlobeGroup.matrixWorld).project(Camera);
      const IsFacingCamera = ProjectedPosition.z < 1;
      const MarkerWorldPosition = MarkerPosition.clone().applyMatrix4(GlobeGroup.matrixWorld);
      const MarkerNormal = MarkerWorldPosition.clone().normalize();
      const ToCameraVector = Camera.position.clone().normalize();
      const IsOnNearSide = MarkerNormal.dot(ToCameraVector) > 0.1;

      if (IsFacingCamera && IsOnNearSide) {
        const ScreenX = (ProjectedPosition.x * 0.5 + 0.5) * ContainerWidth;
        const ScreenY = (-ProjectedPosition.y * 0.5 + 0.5) * ContainerHeight;
        LabelElement.style.left = `${ScreenX}px`;
        LabelElement.style.top = `${ScreenY}px`;
        LabelElement.style.display = "flex";
      } else {
        LabelElement.style.display = "none";
      }

      Renderer.render(Scene, Camera);
      AnimationFrameHandle = requestAnimationFrame(AnimateFrame);
    };
    AnimateFrame();

    this.ActiveGlobeInstances.push({
      ContainerElement: GlobeContainerElement,
      StopAnimation: () => {
        if (AnimationFrameHandle) {
          cancelAnimationFrame(AnimationFrameHandle);
        }
      },
    });
  }

  ConvertLatLonToVector3(Latitude, Longitude, Radius) {
    const PhiAngle = (90 - Latitude) * (Math.PI / 180);
    const ThetaAngle = (Longitude + 180) * (Math.PI / 180);

    const X = -Radius * Math.sin(PhiAngle) * Math.cos(ThetaAngle);
    const Y = Radius * Math.cos(PhiAngle);
    const Z = Radius * Math.sin(PhiAngle) * Math.sin(ThetaAngle);

    return new window.THREE.Vector3(X, Y, Z);
  }

  async FetchWorldLandGeometry() {
    if (AtmosphereClient.CachedWorldLandFeature) {
      return AtmosphereClient.CachedWorldLandFeature;
    }
    if (AtmosphereClient.WorldLandFetchPromise) {
      return AtmosphereClient.WorldLandFetchPromise;
    }

    AtmosphereClient.WorldLandFetchPromise = fetch("https://cdn.jsdelivr.net/npm/world-atlas@2/land-110m.json")
      .then((Response) => Response.json())
      .then((TopologyData) => {
        if (!window.topojson) {
          throw new Error("topojson-client failed to load");
        }
        const LandFeature = window.topojson.feature(TopologyData, TopologyData.objects.land);
        AtmosphereClient.CachedWorldLandFeature = LandFeature;
        return LandFeature;
      })
      .catch((FetchError) => {
        console.error("Failed to load world land geometry:", FetchError);
        AtmosphereClient.WorldLandFetchPromise = null;
        return null;
      });

    return AtmosphereClient.WorldLandFetchPromise;
  }

  async BuildContinentOutlines() {
    const OutlineGroup = new window.THREE.Group();
    const LandFeature = await this.FetchWorldLandGeometry();

    if (!LandFeature) {
      return OutlineGroup;
    }

    const OutlineMaterial = new window.THREE.LineBasicMaterial({ color: 0xbfff4d, transparent: true, opacity: 1, linewidth: 2 });
    const OutlineMaterialGlow = new window.THREE.LineBasicMaterial({ color: 0xbfff4d, transparent: true, opacity: 0.4, linewidth: 4 });

    LandFeature.features.forEach((LandFeatureEntry) => {
      const GeometryType = LandFeatureEntry.geometry.type;
      const PolygonList = GeometryType === "Polygon"
        ? [LandFeatureEntry.geometry.coordinates]
        : LandFeatureEntry.geometry.coordinates;

      PolygonList.forEach((PolygonRings) => {
        if (!PolygonRings || PolygonRings.length === 0) {
          return;
        }

        PolygonRings.forEach((RingCoordinates) => {
          if (!RingCoordinates || RingCoordinates.length < 3) {
            return;
          }

          const RingPositions = [];
          const GlowPositions = [];
          RingCoordinates.forEach(([PointLongitude, PointLatitude]) => {
            const PointVector = this.ConvertLatLonToVector3(PointLatitude, PointLongitude, 1.007);
            RingPositions.push(PointVector.x, PointVector.y, PointVector.z);
            const GlowVector = this.ConvertLatLonToVector3(PointLatitude, PointLongitude, 1.005);
            GlowPositions.push(GlowVector.x, GlowVector.y, GlowVector.z);
          });

          const RingGeometry = new window.THREE.BufferGeometry();
          RingGeometry.setAttribute("position", new window.THREE.BufferAttribute(new Float32Array(RingPositions), 3));
          OutlineGroup.add(new window.THREE.LineLoop(RingGeometry, OutlineMaterial));

          const GlowGeometry = new window.THREE.BufferGeometry();
          GlowGeometry.setAttribute("position", new window.THREE.BufferAttribute(new Float32Array(GlowPositions), 3));
          OutlineGroup.add(new window.THREE.LineLoop(GlowGeometry, OutlineMaterialGlow));
        });
      });
    });

    return OutlineGroup;
  }

  BuildGeoTableHtml(GeoData) {
    return `
      <table class="DataTable">
        ${this.BuildDataRow("City", GeoData.City || "Unknown")}
        ${this.BuildDataRow("Region", GeoData.Region || "Unknown")}
        ${this.BuildDataRow("Country", `${GeoData.Country || "Unknown"} (${GeoData.CountryCode || "-"})`)}
        ${this.BuildDataRow("Continent", GeoData.Continent || "Unknown")}
        ${this.BuildDataRow("Postal Code", GeoData.PostalCode || "Unknown")}
        ${this.BuildDataRow("Latitude", GeoData.Latitude || "0")}
        ${this.BuildDataRow("Longitude", GeoData.Longitude || "0")}
        ${this.BuildDataRow("Altitude", GeoData.Altitude || "Not Available")}
        ${this.BuildDataRow("Timezone", GeoData.Timezone || "Unknown")}
        ${this.BuildDataRow("ISP", GeoData.Isp || "Unknown")}
        ${this.BuildDataRow("Organization", GeoData.Org || "Unknown")}
        ${this.BuildDataRow("ASN", GeoData.Asn || "Unknown")}
        ${this.BuildDataRow("Mobile Network", GeoData.Mobile ? this.WrapBadge("Yes", "Orange") : this.WrapBadge("No", "Green"))}
        ${this.BuildDataRow("Proxy / VPN", GeoData.Proxy ? this.WrapBadge("Detected", "Red") : this.WrapBadge("Not Detected", "Green"))}
        ${this.BuildDataRow("Hosting / Datacenter", GeoData.Hosting ? this.WrapBadge("Yes", "Orange") : this.WrapBadge("No", "Green"))}
        ${this.BuildDataRow("Data Source", GeoData.SourceLabel || "Unknown")}
      </table>
    `;
  }

  RenderSelfScanReport(ReportData, ClientHintPayload) {
    const LocationLine = [ReportData.Geo.City, ReportData.Geo.Region, ReportData.Geo.Country].filter(Boolean).join(", ") || "Location Unresolved";
    const LocalIpsDisplay = (ReportData.Network.LocalIps && ReportData.Network.LocalIps.length > 0) ? ReportData.Network.LocalIps.join(", ") : "Not Detected";

    const HtmlContent = `
      <div class="ExportBar">
        <button class="BtnGithub" id="RefreshButton"><i class="fa-solid fa-rotate-right"></i> Refresh</button>
        <button class="BtnGithub BtnGithub-Primary" id="ExportSelfScanButton"><i class="fa-solid fa-download"></i> Export JSON</button>
      </div>

      ${this.BuildMapSectionHtml(ReportData.Geo)}

      <div class="ResultHeader">
        <span class="ResultHeader-Ip">${ReportData.Geo.Ip || "Unknown"}</span>
        <span class="ResultHeader-Location">${LocationLine}</span>
      </div>

      <div class="SectionLabel"><i class="fa-solid fa-earth-asia"></i> Geolocation</div>
      ${this.BuildGeoTableHtml(ReportData.Geo)}

      <div class="SectionLabel"><i class="fa-solid fa-desktop"></i> Device & Browser</div>
      <table class="DataTable">
        ${this.BuildDataRow("Device Type", this.ResolveDeviceBadge(ReportData.Device.DeviceType))}
        ${this.BuildDataRow("OS Name", ReportData.Device.OsName || "Unknown")}
        ${this.BuildDataRow("OS Version", ReportData.Device.OsVersion || "Unknown")}
        ${this.BuildDataRow("Vendor", ReportData.Device.DeviceVendor || "Unknown")}
        ${this.BuildDataRow("Model", ReportData.Device.DeviceModel || "Unknown")}
        ${this.BuildDataRow("Browser", ReportData.Device.BrowserName || "Unknown")}
        ${this.BuildDataRow("Browser Version", ReportData.Device.BrowserVersion || "Unknown")}
        ${this.BuildDataRow("Engine", `${ReportData.Device.EngineName || "Unknown"} ${ReportData.Device.EngineVersion || ""}`)}
        ${this.BuildDataRow("Bot Detected", ReportData.Device.IsBot ? this.WrapBadge("Yes", "Red") : this.WrapBadge("No", "Green"))}
        ${this.BuildDataRow("Platform", ClientHintPayload.PlatformName || "Unknown")}
        ${this.BuildDataRow("Screen Resolution", `${ClientHintPayload.ScreenWidth} x ${ClientHintPayload.ScreenHeight}`)}
        ${this.BuildDataRow("Pixel Ratio", ClientHintPayload.PixelRatio)}
        ${this.BuildDataRow("Touch Support", ClientHintPayload.TouchSupport ? "Yes" : "No")}
      </table>

      <div class="SectionLabel"><i class="fa-solid fa-network-wired"></i> Network & Client</div>
      <table class="DataTable">
        ${this.BuildDataRow("Public IP", ReportData.Network.PublicIp || "Unknown")}
        ${this.BuildDataRow("Local IP(s)", LocalIpsDisplay)}
        ${this.BuildDataRow("Protocol", ReportData.Network.Protocol || "Unknown")}
        ${this.BuildDataRow("Accept Language", ReportData.Network.AcceptLang || "Unknown")}
        ${this.BuildDataRow("Host Header", ReportData.Network.HostHeader || "Unknown")}
        ${this.BuildDataRow("Hardware Threads", ClientHintPayload.HardwareThreads || "Unknown")}
        ${this.BuildDataRow("Device Memory", ClientHintPayload.DeviceMemory ? `${ClientHintPayload.DeviceMemory} GB` : "Unknown")}
        ${this.BuildDataRow("Connection Type", ClientHintPayload.ConnectionType)}
        ${this.BuildDataRow("Do Not Track", ClientHintPayload.DoNotTrack)}
        ${this.BuildDataRow("Request ID", ReportData.RequestId || "Unknown")}
        ${this.BuildDataRow("Timestamp (UTC)", ReportData.Timestamp || "Unknown")}
      </table>
    `;

    document.getElementById("SelfScanContent").innerHTML = HtmlContent;
    document.getElementById("RefreshButton").addEventListener("click", () => this.RunSelfScan());
    document.getElementById("ExportSelfScanButton").addEventListener("click", () => this.ExportReport(this.LastSelfScanData));
    this.InitializeSatelliteMaps(document.getElementById("SelfScanContent"));
  }

  RenderLookupReport(GeoData, ContentElement) {
    const LocationLine = [GeoData.City, GeoData.Region, GeoData.Country].filter(Boolean).join(", ") || "Location Unresolved";

    const HtmlContent = `
      <div class="ExportBar">
        <button class="BtnGithub BtnGithub-Primary" id="LookupExportButton"><i class="fa-solid fa-download"></i> Export JSON</button>
      </div>

      ${this.BuildMapSectionHtml(GeoData)}

      <div class="ResultHeader">
        <span class="ResultHeader-Ip">${GeoData.Ip || "Unknown"}</span>
        <span class="ResultHeader-Location">${LocationLine}</span>
      </div>

      <div class="SectionLabel"><i class="fa-solid fa-earth-asia"></i> Geolocation</div>
      ${this.BuildGeoTableHtml(GeoData)}
    `;

    ContentElement.innerHTML = HtmlContent;
    document.getElementById("LookupExportButton").addEventListener("click", () => this.ExportReport(this.LastLookupData));
    this.InitializeSatelliteMaps(ContentElement);
  }

  RenderBatchReport(BatchResult, ContentElement) {
    const ResultItemsHtml = (BatchResult.Results || []).map((GeoData) => {
      const LocationLine = [GeoData.City, GeoData.Region, GeoData.Country].filter(Boolean).join(", ") || "Location Unresolved";
      return `
        <div class="BatchResultItem">
          <div class="BatchResultItem-Header">
            <span>${GeoData.Ip}</span>
            <span>${LocationLine}</span>
          </div>
          <div class="BatchResultItem-Body">
            ${this.BuildMapSectionHtml(GeoData)}
            ${this.BuildGeoTableHtml(GeoData)}
          </div>
        </div>
      `;
    }).join("");

    const FailedHtml = (BatchResult.Failed && BatchResult.Failed.length > 0)
      ? `<div class="BatchFailedList">Failed to resolve: ${BatchResult.Failed.join(", ")}</div>`
      : "";

    ContentElement.innerHTML = `
      <div class="ExportBar">
        <button class="BtnGithub BtnGithub-Primary" id="BatchExportButton"><i class="fa-solid fa-download"></i> Export JSON</button>
      </div>
      ${ResultItemsHtml}
      ${FailedHtml}
    `;

    document.getElementById("BatchExportButton").addEventListener("click", () => this.ExportReport(this.LastBatchData));
    this.InitializeSatelliteMaps(ContentElement);
  }

  ExportReport(DataObject) {
    if (!DataObject) {
      return;
    }
    const JsonBlob = new Blob([JSON.stringify(DataObject, null, 2)], { type: "application/json" });
    const DownloadUrl = URL.createObjectURL(JsonBlob);
    const DownloadAnchor = document.createElement("a");
    DownloadAnchor.href = DownloadUrl;
    DownloadAnchor.download = `atmosphere-report-${Date.now()}.json`;
    DownloadAnchor.click();
    URL.revokeObjectURL(DownloadUrl);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const ClientInstance = new AtmosphereClient();
  ClientInstance.RunSelfScan();
});
