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

    this.ViewTitleMap = {
      SelfScan: "Self Scan",
      IpLookup: "IP Lookup",
      BatchLookup: "Batch Lookup",
      DnsTools: "DNS Tools",
      SslCheck: "SSL Certificate",
      WhoisLookup: "Whois Lookup",
      HeaderInspect: "Header Inspector",
      NetworkTools: "Network Tools",
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

    return `
      <div class="SectionLabel"><i class="fa-solid fa-map-location-dot"></i> Location Map</div>
      <div class="MapEmbed" id="${MapContainerId}" data-lat="${GeoData.Latitude}" data-lon="${GeoData.Longitude}" data-label="${GeoData.City || ""}, ${GeoData.Country || ""}"></div>
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
