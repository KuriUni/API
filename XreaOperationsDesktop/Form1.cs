using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace XreaOperationsDesktop;

public sealed partial class Form1 : Form
{
    private const string ApiUrl = "https://2415.jp/license/admin_api.php";
    private const string SsoStartUrl = "https://2415.jp/license/admin_api.php?admin_sso_start=1&return_app=desktop";
    private readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private readonly Label session = new() { Text = "未ログイン", AutoSize = true, ForeColor = Color.DimGray };
    private readonly Label status = new() { Text = "SSO IDでログインしてください。", AutoSize = true, ForeColor = Color.DimGray };
    private readonly Button loginButton = new() { Text = "SSO IDでログイン", AutoSize = true };
    private readonly Button logoutButton = new() { Text = "ログアウト", AutoSize = true, Enabled = false };
    private readonly DataGridView tenantsGrid = MakeGrid();
    private readonly TextBox tenantSearch = new() { PlaceholderText = "名前・slug・IDで検索", Width = 230 };
    private readonly Label tenantOpsSummary = new() { Text = "テナントを選択すると運用操作が表示されます。", AutoSize = true, MaximumSize = new Size(1000, 0) };
    private readonly TextBox tenantEditName = new() { PlaceholderText = "契約者名", Width = 230, Enabled = false };
    private readonly ComboBox tenantEditPlan = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 150, Enabled = false };
    private readonly Button tenantSaveButton = new() { Text = "名称・プランを保存", AutoSize = true, Enabled = false };
    private readonly Button tenantStatusButton = new() { Text = "運用停止／再開", AutoSize = true, Enabled = false };
    private readonly Button tenantSandboxButton = new() { Text = "検証用sandboxを作成", AutoSize = true, Enabled = false };
    private TenantOpsRow? selectedTenant;
    private TenantOpsRow[] currentTenants = [];
    private bool loadingTenants;
    private readonly DataGridView licensesGrid = MakeGrid();
    private readonly DataGridView auditGrid = MakeGrid();
    private readonly DataGridView apiKeysGrid = MakeGrid();
    private readonly DataGridView adminsGrid = MakeGrid();
    private readonly Label overviewApi = new() { Text = "未確認", AutoSize = true };
    private readonly Label overviewHealth = new() { Text = "未確認", AutoSize = true };
    private readonly Label overviewTenants = new() { Text = "—", AutoSize = true };
    private readonly Label overviewLicenses = new() { Text = "—", AutoSize = true };
    private readonly TextBox tenantName = new() { PlaceholderText = "テナント名", Width = 180 };
    private readonly TextBox tenantSlug = new() { PlaceholderText = "slug (example-company)", Width = 200 };
    private readonly ComboBox tenantPlan = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 130 };
    private readonly TextBox licenseTenant = new() { PlaceholderText = "テナントID", Width = 95 };
    private readonly TextBox licenseProduct = new() { PlaceholderText = "製品ID", Width = 95 };
    private readonly TextBox licenseLabel = new() { PlaceholderText = "ラベル", Width = 160 };
    private readonly ComboBox licenseMode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 130 };
    private readonly ComboBox licenseAction = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 185 };
    private readonly CheckBox deletedLicenses = new() { Text = "削除済みを含む", AutoSize = true, Padding = new Padding(0, 8, 0, 0) };
    private readonly NumericUpDown renewDays = new() { Minimum = 1, Maximum = 3650, Value = 30, Width = 70 };
    private readonly NumericUpDown maxDevices = new() { Minimum = 2, Maximum = 500, Value = 10, Width = 80 };
    private readonly TextBox licenseSearch = new() { PlaceholderText = "ID・ラベル・テナント・製品", Width = 250 };
    private readonly ComboBox licenseStatus = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 180 };
    private readonly TextBox auditSearch = new() { PlaceholderText = "対象ID・リクエストID", Width = 220 };
    private readonly TextBox auditEvent = new() { PlaceholderText = "イベント名", Width = 180 };
    private readonly TextBox auditActor = new() { PlaceholderText = "操作者ID先頭8桁", Width = 155, MaxLength = 64 };
    private readonly DateTimePicker auditFrom = new() { Format = DateTimePickerFormat.Short, ShowCheckBox = true, Width = 130 };
    private readonly DateTimePicker auditTo = new() { Format = DateTimePickerFormat.Short, ShowCheckBox = true, Width = 130 };
    private readonly TextBox keyTenant = new() { PlaceholderText = "テナントID", Width = 90 };
    private readonly TextBox keyName = new() { PlaceholderText = "APIクライアント名", Width = 170 };
    private readonly TextBox keyScopes = new() { Text = "tenant:read,licenses:read", Width = 225 };
    private readonly NumericUpDown keyRate = new() { Minimum = 10, Maximum = 10000, Value = 120, Width = 90 };
    private readonly NumericUpDown keyGrace = new() { Minimum = 0, Maximum = 10080, Value = 60, Width = 70 };
    private readonly ComboBox adminRoleChoice = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 170 };
    private readonly TextBox inviteEmail = new() { PlaceholderText = "契約者のメールアドレス", Width = 340 };
    private readonly ComboBox inviteTenant = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 420 };
    private readonly Label inviteResult = new() { Text = "", AutoSize = true, MaximumSize = new Size(760, 0) };
    private string? sessionToken;

    public Form1()
    {
        Text = "TUTI 運用管理";
        MinimumSize = new Size(1000, 650);
        Size = new Size(1250, 800);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Yu Gothic UI", 10F);
        BackColor = Color.FromArgb(244, 247, 247);
        BuildUi();
        loginButton.Click += async (_, _) => await LoginAsync();
        logoutButton.Click += async (_, _) => await LogoutAsync();
    }

    private void BuildUi()
    {
        var top = new Panel { Dock = DockStyle.Top, Height = 76, Padding = new Padding(18), BackColor = Color.White };
        var title = new Label { Text = "TUTI  運用管理", AutoSize = true, Font = new Font(Font, FontStyle.Bold), Location = new Point(18, 12) };
        session.Location = new Point(20, 45);
        loginButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        loginButton.Location = new Point(Width - 310, 20);
        logoutButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        logoutButton.Location = new Point(Width - 160, 20);
        top.Controls.AddRange([title, session, loginButton, logoutButton]);
        top.Resize += (_, _) => { loginButton.Left = top.ClientSize.Width - 300; logoutButton.Left = top.ClientSize.Width - 150; };

        var tabs = new TabControl { Dock = DockStyle.Fill, Padding = new Point(16, 7) };
        tabs.TabPages.Add(BuildOverviewTab());
        tabs.TabPages.Add(BuildTenantsTab());
        tabs.TabPages.Add(BuildApiKeysTab());
        tabs.TabPages.Add(BuildLicensesTab());
        tabs.TabPages.Add(BuildAuditTab());
        tabs.TabPages.Add(BuildAdminsTab());
        tabs.TabPages.Add(BuildContractorInviteTab());
        tabs.SelectedIndexChanged += async (_, _) => await LoadCurrentTab(tabs.SelectedIndex);
        status.Dock = DockStyle.Bottom;
        status.Height = 30;
        status.Padding = new Padding(12, 6, 0, 0);
        Controls.Add(tabs);
        Controls.Add(status);
        Controls.Add(top);
    }

    private TabPage BuildOverviewTab()
    {
        var page = new TabPage("概要");
        var panel = new FlowLayoutPanel { Dock = DockStyle.Top, Padding = new Padding(22), AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = true };
        panel.Controls.Add(Metric("管理API", overviewApi));
        panel.Controls.Add(Metric("サービス準備状態", overviewHealth));
        panel.Controls.Add(Metric("テナント", overviewTenants));
        panel.Controls.Add(Metric("ライセンス", overviewLicenses));
        var refresh = new Button { Text = "状況を更新", AutoSize = true, Margin = new Padding(14) };
        refresh.Click += async (_, _) => await RefreshOverviewAsync();
        panel.Controls.Add(refresh);
        var hint = new Label { Text = "よく使う操作は上部のタブから開けます。操作履歴は監査ログに記録されます。", AutoSize = true, Padding = new Padding(22) };
        page.Controls.Add(hint);
        page.Controls.Add(panel);
        return page;
    }

    private static Control Metric(string title, Label value)
    {
        var box = new Panel { Width = 235, Height = 112, Margin = new Padding(10), Padding = new Padding(14), BackColor = Color.White };
        box.Controls.Add(new Label { Text = title, AutoSize = true, ForeColor = Color.DimGray, Location = new Point(14, 14) });
        value.Font = new Font("Yu Gothic UI", 18, FontStyle.Bold);
        value.Location = new Point(14, 48);
        box.Controls.Add(value);
        return box;
    }

    private TabPage BuildTenantsTab()
    {
        var page = new TabPage("テナント");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 58, Padding = new Padding(8), WrapContents = false };
        tenantPlan.Items.AddRange(["standard", "trial", "business", "enterprise"]);
        tenantPlan.SelectedIndex = 0;
        var create = new Button { Text = "テナント作成", AutoSize = true };
        var refresh = new Button { Text = "一覧を更新", AutoSize = true };
        create.Click += async (_, _) => await CreateTenantAsync();
        refresh.Click += async (_, _) => await LoadTenantsAsync();
        tenantEditPlan.Items.AddRange(["standard", "trial", "business", "enterprise"]);
        tenantEditPlan.SelectedIndex = 0;
        tenantSearch.TextChanged += (_, _) => ApplyTenantFilter();
        tenantSaveButton.Click += async (_, _) => await SaveTenantAsync();
        tenantStatusButton.Click += async (_, _) => await ToggleTenantStatusAsync();
        tenantSandboxButton.Click += async (_, _) => await CreateTenantSandboxAsync();
        tenantsGrid.SelectionChanged += async (_, _) => { if (!loadingTenants) await SelectOperatingTenantAsync(); };
        bar.Controls.AddRange([tenantSearch, new Label { Text = "新規", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }, tenantName, tenantSlug, tenantPlan, create, refresh]);
        tenantsGrid.Dock = DockStyle.Fill;
        var ops = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 106, Padding = new Padding(10), WrapContents = true, BackColor = Color.White };
        ops.Controls.Add(tenantOpsSummary);
        ops.Controls.AddRange([new Label { Text = "運用変更:", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }, tenantEditName,
            new Label { Text = "プラン", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }, tenantEditPlan,
            tenantSaveButton, tenantStatusButton, tenantSandboxButton]);
        page.Controls.Add(tenantsGrid);
        page.Controls.Add(ops);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildLicensesTab()
    {
        var page = new TabPage("ライセンス");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 104, Padding = new Padding(8), WrapContents = true };
        licenseStatus.Items.AddRange(["すべて", "active", "paused", "revoked", "expired", "expiring"]);
        licenseStatus.SelectedIndex = 0;
        licenseMode.Items.AddRange(["single", "volume", "evaluation"]);
        licenseMode.SelectedIndex = 0;
        var issue = new Button { Text = "ライセンス発行", AutoSize = true };
        var refresh = new Button { Text = "検索・更新", AutoSize = true };
        licenseAction.Items.AddRange(["停止／再開", "端末を強制再認証", "有効期限を延長", "削除（復元可能）", "削除済みを復元"]);
        licenseAction.SelectedIndex = 0;
        var stateAction = new Button { Text = "選択行に実行", AutoSize = true };
        issue.Click += async (_, _) => await CreateLicenseAsync();
        refresh.Click += async (_, _) => await LoadLicensesAsync();
        stateAction.Click += async (_, _) => await ApplyLicenseActionAsync();
        deletedLicenses.CheckedChanged += async (_, _) => await LoadLicensesAsync();
        bar.Controls.AddRange([licenseSearch, licenseStatus, deletedLicenses, new Label { Text = "テナントID", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }, licenseTenant, new Label { Text = "製品ID", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }, licenseProduct, licenseLabel, licenseMode, new Label { Text = "最大端末数", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }, maxDevices, issue, refresh, licenseAction, new Label { Text = "延長日数", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }, renewDays, stateAction]);
        licensesGrid.Dock = DockStyle.Fill;
        page.Controls.Add(licensesGrid);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildApiKeysTab()
    {
        var page = new TabPage("テナントAPIキー");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 102, Padding = new Padding(8), WrapContents = true };
        var load = new Button { Text = "一覧を更新", AutoSize = true };
        var issue = new Button { Text = "APIキーを発行", AutoSize = true };
        var rotate = new Button { Text = "選択キーを更新", AutoSize = true };
        var revoke = new Button { Text = "選択キーを失効", AutoSize = true };
        load.Click += async (_, _) => await LoadApiKeysAsync();
        issue.Click += async (_, _) => await IssueApiKeyAsync();
        rotate.Click += async (_, _) => await RotateApiKeyAsync();
        revoke.Click += async (_, _) => await RevokeApiKeyAsync();
        bar.Controls.AddRange([keyTenant, keyName, keyScopes, new Label { Text = "毎分上限", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }, keyRate, new Label { Text = "更新猶予(分)", AutoSize = true, Padding = new Padding(0, 8, 0, 0) }, keyGrace, load, issue, rotate, revoke]);
        apiKeysGrid.Dock = DockStyle.Fill;
        page.Controls.Add(apiKeysGrid);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildAuditTab()
    {
        var page = new TabPage("監査ログ");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 58, Padding = new Padding(8), WrapContents = false };
        var refresh = new Button { Text = "監査ログを検索", AutoSize = true };
        refresh.Click += async (_, _) => await LoadAuditAsync();
        bar.Controls.AddRange([auditSearch, auditEvent, auditActor, auditFrom, auditTo, refresh]);
        auditGrid.Dock = DockStyle.Fill;
        var details = new TextBox { Dock = DockStyle.Bottom, Height = 120, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, PlaceholderText = "行を選ぶと操作前後の詳細を表示します。" };
        auditGrid.SelectionChanged += (_, _) =>
        {
            if (auditGrid.CurrentRow?.DataBoundItem is AuditRow row) details.Text = $"操作者: {row.ActorHash}\r\n変更内容: {row.Change}";
        };
        page.Controls.Add(auditGrid);
        page.Controls.Add(details);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildAdminsTab()
    {
        var page = new TabPage("管理者権限");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 58, Padding = new Padding(8), WrapContents = false };
        adminRoleChoice.Items.AddRange(["viewer", "operator", "security-admin", "ha-admin"]);
        adminRoleChoice.SelectedIndex = 0;
        var load = new Button { Text = "管理者一覧を更新", AutoSize = true };
        var change = new Button { Text = "選択管理者の権限を変更（Passkey再認証）", AutoSize = true };
        load.Click += async (_, _) => await LoadAdminsAsync();
        change.Click += async (_, _) => await ChangeAdminRoleAsync();
        bar.Controls.AddRange([load, adminRoleChoice, change]);
        adminsGrid.Dock = DockStyle.Fill;
        page.Controls.Add(adminsGrid);
        page.Controls.Add(bar);
        return page;
    }

    private TabPage BuildContractorInviteTab()
    {
        var page = new TabPage("契約者SSO招待");
        var panel = new FlowLayoutPanel { Dock = DockStyle.Top, Padding = new Padding(24), AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        panel.Controls.Add(new Label { Text = "契約者を共通SSOへ招待", AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
        panel.Controls.Add(new Label { Text = "本人確認メールを送信します。受信者がメールを確認し、Passkeyを登録するとSSO IDを利用できます。", AutoSize = true, MaximumSize = new Size(850, 0), Padding = new Padding(0, 12, 0, 8) });
        panel.Controls.Add(new Label { Text = "Tenant account (tenant ID)", AutoSize = true, Padding = new Padding(0, 12, 0, 4) });
        panel.Controls.Add(inviteTenant);
        panel.Controls.Add(inviteEmail);
        var invite = new Button { Text = "Passkey再認証して招待メールを送信", AutoSize = true, Margin = new Padding(0, 14, 0, 8) };
        invite.Click += async (_, _) => await InviteContractorAsync();
        panel.Controls.Add(invite);
        panel.Controls.Add(inviteResult);
        page.Controls.Add(panel);
        return page;
    }

    private static DataGridView MakeGrid() => new()
    {
        ReadOnly = true,
        AllowUserToAddRows = false,
        AllowUserToDeleteRows = false,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        MultiSelect = false,
        BackgroundColor = Color.White,
        BorderStyle = BorderStyle.None,
        RowHeadersVisible = false
    };

    private async Task LoginAsync(bool stepUp = false)
    {
        var previousToken = sessionToken;
        loginButton.Enabled = false;
        try
        {
            using var callback = new DesktopCallback();
            var state = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            var redirect = $"http://127.0.0.1:{callback.Port}/callback";
            var url = SsoStartUrl + (stepUp ? "&step_up=1" : "") + "&desktop_redirect=" + Uri.EscapeDataString(redirect) + "&desktop_state=" + state;
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            SetStatus("既定のブラウザーでSSO IDにログインしてください。");
            var token = await callback.WaitAsync(state, TimeSpan.FromMinutes(5));
            sessionToken = token;
            SetStatus("SSO IDで認証しました。権限を確認しています。");
            await ApiAsync("ping");
            session.Text = "SSO IDでログイン中";
            session.ForeColor = Color.DarkGreen;
            loginButton.Enabled = false;
            logoutButton.Enabled = true;
            await LoadTenantsAsync();
            await RefreshOverviewAsync();
            SetStatus(stepUp ? "Passkeyで再認証しました。120秒以内に管理操作を実行できます。" : "ログインしました。");
        }
        catch (Exception ex) { sessionToken = previousToken; SetStatus("ログイン失敗: " + ex.Message, true); }
        finally { loginButton.Enabled = sessionToken is null; }
    }

    private async Task LogoutAsync()
    {
        try { if (sessionToken is not null) await ApiAsync("logout"); } catch { }
        sessionToken = null;
        session.Text = "未ログイン";
        session.ForeColor = Color.DimGray;
        loginButton.Enabled = true;
        logoutButton.Enabled = false;
        SetStatus("ログアウトしました。");
    }

    private async Task LoadCurrentTab(int index)
    {
        if (sessionToken is null) return;
        if (index == 1) await LoadTenantsAsync();
        if (index == 2) await LoadApiKeysAsync();
        if (index == 3) await LoadLicensesAsync();
        if (index == 4) await LoadAuditAsync();
        if (index == 5) await LoadAdminsAsync();
        if (index == 6) await LoadTenantsAsync();
    }

    private async Task RefreshOverviewAsync()
    {
        if (sessionToken is null) { SetStatus("SSO IDでログインしてください。", true); return; }
        try
        {
            await ApiAsync("ping");
            overviewApi.Text = "接続中";
            using var health = await http.GetAsync("https://2415.jp/license/ha/health.php");
            using var json = JsonDocument.Parse(await health.Content.ReadAsStringAsync());
            var ready = health.IsSuccessStatusCode && json.RootElement.TryGetProperty("ok", out var ok) && ok.GetBoolean();
            overviewHealth.Text = ready ? "正常" : "要確認";
            overviewTenants.Text = await CountRowsAsync("list_tenants", "tenants");
            overviewLicenses.Text = await CountRowsAsync("list_licenses", "licenses");
            SetStatus("管理APIとサービス状態を更新しました。");
        }
        catch (Exception ex) { overviewApi.Text = "要確認"; overviewHealth.Text = "要確認"; SetStatus(ex.Message, true); }
    }

    private async Task<string> CountRowsAsync(string action, string property)
    {
        var result = await ApiAsync(action, new { page = 1, limit = 1 });
        var hasNext = result.TryGetProperty("has_next", out var more) && more.GetBoolean();
        return hasNext ? "1件以上" : result.GetProperty(property).GetArrayLength().ToString();
    }

    private async Task<JsonElement> ApiAsync(string action, object? fields = null)
    {
        if (sessionToken is null) throw new InvalidOperationException("先にSSO IDでログインしてください。");
        var payload = new Dictionary<string, object?> { ["action"] = action };
        if (fields is not null)
            foreach (var property in JsonSerializer.SerializeToElement(fields).EnumerateObject()) payload[property.Name] = property.Value.Clone();
        using var request = new HttpRequestMessage(HttpMethod.Post, ApiUrl) { Content = JsonContent.Create(payload) };
        request.Headers.TryAddWithoutValidation("X-HA-Session", sessionToken);
        request.Headers.TryAddWithoutValidation("Origin", "https://2415.jp");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        using var response = await http.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (!response.IsSuccessStatusCode || !root.TryGetProperty("success", out var success) || !success.GetBoolean())
        {
            var message = root.TryGetProperty("message", out var msg) ? msg.GetString() : "管理APIでエラーが発生しました。";
            throw new InvalidOperationException(message ?? $"HTTP {(int)response.StatusCode}");
        }
        return root.Clone();
    }

    private async Task<JsonElement> TenantAdminAsync(HttpMethod method, string query, object? fields)
    {
        if (sessionToken is null) throw new InvalidOperationException("先にSSO IDでログインしてください。");
        var url = "https://2415.jp/license/ha/tenant-admin.php" + query;
        using var request = new HttpRequestMessage(method, url);
        request.Headers.TryAddWithoutValidation("X-HA-Session", sessionToken);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        if (fields is not null) request.Content = JsonContent.Create(fields);
        using var response = await http.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        if (!response.IsSuccessStatusCode || !root.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
        {
            var message = root.TryGetProperty("message", out var msg) ? msg.GetString() : null;
            if (string.IsNullOrEmpty(message) && root.TryGetProperty("error", out var err)) message = TenantErrorMessage(err.GetString() ?? "");
            throw new InvalidOperationException(message ?? $"テナント管理API HTTP {(int)response.StatusCode}");
        }
        return root.Clone();
    }

    private static string TenantErrorMessage(string code) => code switch
    {
        "server_not_writable" => "現在このサーバーは書き込み停止中です。プライマリの稼働状態を確認してください。",
        "protected_or_invalid_tenant" => "この契約者は保護されているか、IDが正しくありません。",
        "production_tenant_not_found_or_inactive" => "運用中のproductionテナントを選択してください。",
        "tenant_not_found" => "契約者が見つかりません。更新してから再操作してください。",
        "invalid_tenant" => "契約者名またはプランが正しくありません。",
        "invalid_plan" => "プランを選択し直してください。",
        _ => "テナント管理を完了できませんでした。" + (code.Length > 0 ? " (" + code + ")" : "")
    };

    private async Task LoadTenantsAsync()
    {
        try
        {
            loadingTenants = true;
            var result = await TenantAdminAsync(HttpMethod.Get, "", null);
            currentTenants = result.GetProperty("tenants").EnumerateArray().Select(x => new TenantOpsRow(
                Val(x, "id"), Val(x, "parent_tenant_id"), Val(x, "slug"), Val(x, "name"), Val(x, "status"), Val(x, "plan_code"), Val(x, "environment"),
                Val(x, "products"), Val(x, "licenses"), Val(x, "active_api_clients"), Val(x, "max_products"), Val(x, "max_licenses"), Val(x, "created_at"), Val(x, "updated_at"))).ToArray();
            ApplyTenantFilter();
            inviteTenant.DataSource = currentTenants.Where(x => x.Status == "active").Select(x => new TenantChoice(x.Id, $"{x.Name} (tenant ID {x.Id}, {x.Slug})")).ToArray();
            inviteTenant.DisplayMember = nameof(TenantChoice.Display);
            inviteTenant.ValueMember = nameof(TenantChoice.Id);
            loadingTenants = false;
            if (tenantsGrid.CurrentRow?.DataBoundItem is TenantOpsRow selected) { selectedTenant = selected; await SelectOperatingTenantAsync(); }
            SetStatus($"契約者 {currentTenants.Length} 件を表示しています。");
        }
        catch (Exception ex) { loadingTenants = false; SetStatus(ex.Message, true); }
    }

    private void ApplyTenantFilter()
    {
        var query = tenantSearch.Text.Trim();
        var visible = currentTenants.Where(x => string.IsNullOrEmpty(query) ||
            x.Id.Contains(query, StringComparison.OrdinalIgnoreCase) || x.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || x.Slug.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray();
        loadingTenants = true;
        tenantsGrid.DataSource = visible;
        SetGridHeaders(tenantsGrid, (nameof(TenantOpsRow.Id), "ID"), (nameof(TenantOpsRow.Name), "契約者"), (nameof(TenantOpsRow.Slug), "Slug"),
            (nameof(TenantOpsRow.Status), "状態"), (nameof(TenantOpsRow.Environment), "環境"), (nameof(TenantOpsRow.Plan), "プラン"),
            (nameof(TenantOpsRow.Products), "製品"), (nameof(TenantOpsRow.Licenses), "有効License"), (nameof(TenantOpsRow.ActiveApiClients), "稼働APIキー"),
            (nameof(TenantOpsRow.MaxProducts), "製品上限"), (nameof(TenantOpsRow.MaxLicenses), "License上限"));
        loadingTenants = false;
        if (tenantsGrid.CurrentRow?.DataBoundItem is not TenantOpsRow) { selectedTenant = null; _ = SelectOperatingTenantAsync(); }
    }

    private static void SetGridHeaders(DataGridView grid, params (string Key, string Label)[] columns)
    {
        foreach (var (key, label) in columns) if (grid.Columns.Contains(key)) grid.Columns[key].HeaderText = label;
    }

    private Task SelectOperatingTenantAsync()
    {
        selectedTenant = tenantsGrid.CurrentRow?.DataBoundItem as TenantOpsRow;
        if (selectedTenant is null)
        {
            tenantOpsSummary.Text = "テナントを選択してください。";
            tenantEditName.Enabled = tenantEditPlan.Enabled = tenantSaveButton.Enabled = tenantStatusButton.Enabled = tenantSandboxButton.Enabled = false;
            return Task.CompletedTask;
        }
        var t = selectedTenant;
        keyTenant.Text = t.Id;
        tenantEditName.Text = t.Name;
        tenantEditPlan.SelectedItem = t.Plan;
        tenantEditName.Enabled = tenantEditPlan.Enabled = tenantSaveButton.Enabled = int.TryParse(t.Id, out var id) && id > 1;
        tenantStatusButton.Enabled = int.TryParse(t.Id, out id) && id > 1;
        var hasSandbox = currentTenants.Any(x => x.ParentTenantId == t.Id || (t.Environment == "sandbox" && x.Id == t.Id));
        tenantSandboxButton.Enabled = t.Environment == "production" && t.Status == "active" && !hasSandbox;
        tenantStatusButton.Text = t.Status == "active" ? "契約を一時停止" : "契約を再開";
        tenantOpsSummary.Text = $"#{t.Id}  {t.Name} ({t.Slug})　{(t.Status == "active" ? "運用中" : "停止中")}　環境 {t.Environment}{(t.ParentTenantId.Length > 0 ? " / 親 #" + t.ParentTenantId : "")}　製品 {t.Products}/{t.MaxProducts}　稼働ライセンス {t.Licenses}/{t.MaxLicenses}　稼働APIキー {t.ActiveApiClients}　作成 {t.CreatedAt}";
        return Task.CompletedTask;
    }

    private async Task CreateTenantAsync()
    {
        if (string.IsNullOrWhiteSpace(tenantName.Text) || string.IsNullOrWhiteSpace(tenantSlug.Text)) { SetStatus("テナント名とslugを入力してください。", true); return; }
        if (MessageBox.Show($"テナント「{tenantName.Text}」を作成しますか？", "テナント作成", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        try
        {
            var data = await TenantAdminAsync(HttpMethod.Post, "", new { action = "create_tenant", name = tenantName.Text.Trim(), slug = tenantSlug.Text.Trim(), plan_code = tenantPlan.Text });
            tenantName.Clear(); tenantSlug.Clear();
            MessageBox.Show($"作成しました。\r\nテナントID: {Val(data, "tenant_id")}\r\n初期製品ID: {Val(data, "default_product_id")}", "完了", MessageBoxButtons.OK, MessageBoxIcon.Information);
            await LoadTenantsAsync();
        }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task SaveTenantAsync()
    {
        if (selectedTenant is null || !int.TryParse(selectedTenant.Id, out var id) || id <= 1) return;
        if (string.IsNullOrWhiteSpace(tenantEditName.Text)) { SetStatus("契約者名を入力してください。", true); return; }
        var plan = tenantEditPlan.SelectedItem?.ToString() ?? "standard";
        if (MessageBox.Show($"契約者 #{id} の情報を更新しますか？\r\n名称: {tenantEditName.Text}\r\nプラン: {plan}\r\nプラン上限を超えている既存データは削除されませんが、新規作成が制限される場合があります。", "契約者情報の更新", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try { await TenantAdminAsync(HttpMethod.Post, "", new { action = "update_tenant", tenant_id = id, name = tenantEditName.Text.Trim(), plan_code = plan }); await LoadTenantsAsync(); SetStatus("契約者情報を更新しました。"); }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task ToggleTenantStatusAsync()
    {
        if (selectedTenant is null || !int.TryParse(selectedTenant.Id, out var id) || id <= 1) return;
        var suspend = selectedTenant.Status == "active";
        var action = suspend ? "suspend_tenant" : "resume_tenant";
        var description = suspend ? "この契約者のAPIアクセスを停止し、稼働中のAPIキーも一時停止します。" : "契約者と一時停止中のAPIキーを再開します。";
        if (MessageBox.Show($"契約者 #{id} を{(suspend ? "一時停止" : "再開")}しますか？\r\n{description}\r\nAPIアクセス停止は操作完了後すぐ反映されます。", "契約運用状態", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try { await TenantAdminAsync(HttpMethod.Post, "", new { action, tenant_id = id }); await LoadTenantsAsync(); SetStatus(suspend ? "契約を一時停止しました。" : "契約を再開しました。"); }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task CreateTenantSandboxAsync()
    {
        if (selectedTenant is null || !int.TryParse(selectedTenant.Id, out var id)) return;
        if (MessageBox.Show($"契約者 #{id} の検証用sandbox環境を作成しますか？", "Sandbox作成", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        try
        {
            var result = await TenantAdminAsync(HttpMethod.Post, "", new { action = "ensure_sandbox", tenant_id = id });
            var created = result.TryGetProperty("created", out var createdValue) && createdValue.ValueKind == JsonValueKind.True;
            MessageBox.Show($"Sandbox {(created ? "を作成しました" : "は既にあります")}。\r\nID: {Val(result, "sandbox_tenant_id")}\r\nSlug: {Val(result, "sandbox_slug")}", "Sandbox", MessageBoxButtons.OK, MessageBoxIcon.Information);
            await LoadTenantsAsync();
        }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task LoadLicensesAsync()
    {
        try
        {
            var result = await ApiAsync(deletedLicenses.Checked ? "list_deleted_licenses" : "list_licenses", new { q = licenseSearch.Text.Trim(), status = deletedLicenses.Checked || licenseStatus.SelectedIndex <= 0 ? "" : licenseStatus.Text, page = 1, limit = 100 });
            var rows = result.GetProperty("licenses").EnumerateArray().Select(x => new LicenseRow(
                Val(x, "id"), Val(x, "tenant_id"), Val(x, "tenant_name"), Val(x, "product_id"), Val(x, "product_name"), Val(x, "label"),
                LicenseState(x), Val(x, "active_sessions"), Val(x, "expires_at"), Val(x, "active"))).ToArray();
            licensesGrid.DataSource = rows;
            SetStatus($"ライセンス {rows.Length} 件");
        }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task CreateLicenseAsync()
    {
        if (!int.TryParse(licenseTenant.Text, out var tenantId) || !int.TryParse(licenseProduct.Text, out var productId)) { SetStatus("テナントIDと製品IDを数値で入力してください。", true); return; }
        if (MessageBox.Show($"テナントID {tenantId} / 製品ID {productId} に発行しますか？\r\n発行キーは今回だけ表示されます。", "ライセンス発行", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try
        {
            var result = await ApiAsync("create_license", new { tenant_id = tenantId, product_id = productId, license_mode = licenseMode.Text, label = licenseLabel.Text.Trim(), max_devices = (int)maxDevices.Value, evaluation_days = 30, expires_at = "" });
            var key = Val(result, "product_key");
            if (MessageBox.Show($"ライセンスキー（この画面を閉じると再表示できません）:\r\n\r\n{key}\r\n\r\nクリップボードにコピーしますか？", "発行完了", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes) Clipboard.SetText(key);
            await LoadLicensesAsync();
        }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task ApplyLicenseActionAsync()
    {
        if (licensesGrid.CurrentRow?.DataBoundItem is not LicenseRow row) { SetStatus("先にライセンスを選択してください。", true); return; }
        var id = int.Parse(row.Id);
        var choice = licenseAction.SelectedItem?.ToString() ?? "";
        var action = choice switch { "停止／再開" => row.Active == "1" ? "pause_license" : "resume_license", "端末を強制再認証" => "force_reauth_license", "有効期限を延長" => "renew_license", "削除（復元可能）" => "delete_license", "削除済みを復元" => "restore_license", _ => "" };
        if (action.Length == 0) return;
        var confirm = action switch
        {
            "pause_license" => $"ライセンス #{id} を停止しますか？登録端末のセッションも失効します。",
            "resume_license" => $"ライセンス #{id} を再開しますか？",
            "force_reauth_license" => $"ライセンス #{id} の全端末を強制再認証しますか？",
            "renew_license" => $"ライセンス #{id} の有効期限を {renewDays.Value} 日延長しますか？",
            "delete_license" => $"ライセンス #{id} を削除しますか？登録端末は失効します。削除済み一覧から復元できます。",
            _ => $"ライセンス #{id} を停止状態で復元しますか？"
        };
        if (MessageBox.Show(confirm, "ライセンス管理", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try
        {
            object payload = action == "renew_license" ? new { license_id = id, renew_days = (int)renewDays.Value } : action == "delete_license" ? new { license_id = id, reason = "administrator_request" } : new { license_id = id };
            var result = await ApiAsync(action, payload);
            SetStatus(Val(result, "message"));
            await LoadLicensesAsync();
        }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task LoadAuditAsync()
    {
        try
        {
            var result = await ApiAsync("list_audit_logs", new { q = auditSearch.Text.Trim(), event_type = auditEvent.Text.Trim(), actor = auditActor.Text.Trim(), from = auditFrom.Checked ? auditFrom.Value.ToString("yyyy-MM-dd") : "", to = auditTo.Checked ? auditTo.Value.ToString("yyyy-MM-dd") : "", page = 1, limit = 100 });
            var rows = result.GetProperty("logs").EnumerateArray().Select(x => new AuditRow(
                Val(x, "created_at"), Val(x, "event_type"), Val(x, "target_type"), Val(x, "target_id"), Val(x, "role_name"), Val(x, "node_role"),
                Val(x, "actor_hash"), "前: " + (x.TryGetProperty("before", out var before) ? before.ToString() : "-") + "\r\n後: " + (x.TryGetProperty("after", out var after) ? after.ToString() : "-"))).ToArray();
            auditGrid.DataSource = rows;
            SetStatus($"監査ログ {rows.Length} 件");
        }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task LoadApiKeysAsync()
    {
        try
        {
            JsonElement result;
            if (int.TryParse(keyTenant.Text.Trim(), out var tenantId) && tenantId > 0)
                result = await TenantAdminAsync(HttpMethod.Get, "?tenant_id=" + tenantId, null);
            else
                result = await ApiAsync("list_tenant_api_keys", new { page = 1, limit = 100 });
            var rows = result.GetProperty("api_clients").EnumerateArray().Select(x => new ApiKeyRow(
                Val(x, "id"), Val(x, "tenant_id"), Val(x, "tenant_name"), Val(x, "name"), Val(x, "key_prefix"), Val(x, "scopes_json"),
                Val(x, "status"), Val(x, "last_used_at"), Val(x, "expires_at"), Val(x, "revoked_at")))
                .Where(x => !int.TryParse(keyTenant.Text.Trim(), out var filterId) || filterId <= 0 || x.TenantId == filterId.ToString()).ToArray();
            apiKeysGrid.DataSource = rows;
            SetGridHeaders(apiKeysGrid, (nameof(ApiKeyRow.Id), "ID"), (nameof(ApiKeyRow.TenantId), "Tenant ID"), (nameof(ApiKeyRow.Tenant), "契約者"),
                (nameof(ApiKeyRow.Name), "APIクライアント"), (nameof(ApiKeyRow.Prefix), "キーprefix"), (nameof(ApiKeyRow.Scopes), "権限"),
                (nameof(ApiKeyRow.Status), "状態"), (nameof(ApiKeyRow.LastUsed), "最終利用"), (nameof(ApiKeyRow.ExpiresAt), "期限"), (nameof(ApiKeyRow.RevokedAt), "失効日時"));
            SetStatus($"APIクライアント {rows.Length} 件");
        }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task IssueApiKeyAsync()
    {
        if (!int.TryParse(keyTenant.Text, out var tenantId) || string.IsNullOrWhiteSpace(keyName.Text)) { SetStatus("テナントIDとAPIクライアント名を入力してください。", true); return; }
        if (MessageBox.Show($"テナントID {tenantId} 用のAPIキーを発行しますか？秘密キーは一度だけ表示されます。", "APIキー発行", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try
        {
            var result = await ApiAsync("issue_tenant_api_key", new { tenant_id = tenantId, client_name = keyName.Text.Trim(), scopes = keyScopes.Text.Trim(), rate_limit_per_minute = (int)keyRate.Value, api_key_expires_at = "" });
            ShowSecret(Val(result, "key"), "APIキーを発行しました");
            await LoadApiKeysAsync();
        }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task RotateApiKeyAsync()
    {
        if (apiKeysGrid.CurrentRow?.DataBoundItem is not ApiKeyRow row || !int.TryParse(row.Id, out var id)) { SetStatus("更新するAPIキーを一覧から選択してください。", true); return; }
        if (row.Status != "active") { SetStatus("有効なAPIキーだけ更新できます。", true); return; }
        if (MessageBox.Show($"APIクライアント #{id} のキーを更新しますか？旧キーは最大 {keyGrace.Value} 分間だけ併用できます。0分なら直ちに失効します。", "APIキー更新", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try { var result = await ApiAsync("rotate_tenant_api_key", new { client_id = id, grace_minutes = (int)keyGrace.Value }); ShowSecret(Val(result, "key"), "APIキーを更新しました"); await LoadApiKeysAsync(); }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task RevokeApiKeyAsync()
    {
        if (apiKeysGrid.CurrentRow?.DataBoundItem is not ApiKeyRow row || !int.TryParse(row.Id, out var id)) { SetStatus("失効するAPIキーを一覧から選択してください。", true); return; }
        if (MessageBox.Show($"APIクライアント #{id} を失効しますか？この操作は元に戻せません。", "APIキー失効", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try { await ApiAsync("revoke_tenant_api_key", new { client_id = id }); await LoadApiKeysAsync(); SetStatus("APIキーを失効しました。"); }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private void ShowSecret(string secret, string title)
    {
        using var dialog = new Form { Text = title, StartPosition = FormStartPosition.CenterParent, Size = new Size(700, 190), MinimizeBox = false, MaximizeBox = false, FormBorderStyle = FormBorderStyle.FixedDialog };
        var text = new TextBox { Text = secret, ReadOnly = true, Dock = DockStyle.Top, Margin = new Padding(12), Font = new Font("Consolas", 11), Width = 640 };
        var copy = new Button { Text = "コピー", AutoSize = true, Location = new Point(12, 50) };
        var close = new Button { Text = "閉じる", AutoSize = true, Location = new Point(105, 50) };
        copy.Click += (_, _) => { Clipboard.SetText(secret); SetStatus("秘密キーをクリップボードへコピーしました。安全な場所に保管してください。"); };
        close.Click += (_, _) => dialog.Close();
        dialog.Controls.Add(text); dialog.Controls.Add(copy); dialog.Controls.Add(close);
        dialog.ShowDialog(this);
    }

    private async Task LoadAdminsAsync()
    {
        try
        {
            var result = await ApiAsync("list_admin_principals");
            adminsGrid.DataSource = result.GetProperty("admin_principals").EnumerateArray().Select(x => new AdminRow(
                Val(x, "id"), Val(x, "display_name"), Val(x, "role_name"), Val(x, "last_login_at"))).ToArray();
            SetStatus("有効な管理者を表示しています。権限変更は毎回Passkey再認証が必要です。");
        }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task ChangeAdminRoleAsync()
    {
        if (adminsGrid.CurrentRow?.DataBoundItem is not AdminRow row || !int.TryParse(row.Id, out var id)) { SetStatus("権限を変更する管理者を一覧から選択してください。", true); return; }
        var role = adminRoleChoice.SelectedItem?.ToString() ?? "viewer";
        if (role == row.Role) { SetStatus("選択した権限は現在の設定と同じです。"); return; }
        if (MessageBox.Show($"{row.Name}（ID {id}）の権限を {row.Role} から {role} に変更しますか？\r\nPasskeyによる再認証が必要です。", "管理者権限変更", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        var before = sessionToken;
        await LoginAsync(stepUp: true);
        if (sessionToken is null || sessionToken == before) return;
        try { await ApiAsync("set_admin_role", new { principal_id = id, role_name = role }); await LoadAdminsAsync(); SetStatus("管理者権限を更新しました。"); }
        catch (Exception ex) { SetStatus(ex.Message, true); }
    }

    private async Task InviteContractorAsync()
    {
        var email = inviteEmail.Text.Trim();
        if (inviteTenant.SelectedValue is not string tenantId || !long.TryParse(tenantId, out _)) { inviteResult.Text = "Select an active tenant first."; return; }
        try
        {
            var address = new System.Net.Mail.MailAddress(email);
            if (!string.Equals(address.Address, email, StringComparison.OrdinalIgnoreCase)) throw new FormatException();
        }
        catch { inviteResult.Text = "有効なメールアドレスを入力してください。"; SetStatus(inviteResult.Text, true); return; }
        if (MessageBox.Show($"契約者向けSSOの招待メールを {email} に送信しますか？\r\n送信前にPasskeyで再認証します。", "契約者SSO招待", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        var before = sessionToken;
        inviteResult.Text = "Passkey再認証を待っています。";
        await LoginAsync(stepUp: true);
        if (sessionToken is null || sessionToken == before) { inviteResult.Text = "再認証を完了できませんでした。"; return; }
        try
        {
            var result = await ApiAsync("create_contractor_sso", new { contractor_email = email, tenant_id = long.Parse(tenantId) });
            inviteResult.Text = Val(result, "message");
            inviteEmail.Clear();
            SetStatus("契約者向けSSO招待を送信しました。");
        }
        catch (Exception ex) { inviteResult.Text = ex.Message; SetStatus(ex.Message, true); }
    }

    private static string Val(JsonElement obj, string key) => obj.TryGetProperty(key, out var value) && value.ValueKind is not JsonValueKind.Null and not JsonValueKind.Undefined ? value.ToString() : "";
    private static string LicenseState(JsonElement row)
    {
        if (Val(row, "deleted_at") != "") return "削除済み";
        if (Val(row, "revoked_at") != "") return "失効";
        if (Val(row, "active") == "0") return "停止";
        if (DateTime.TryParse(Val(row, "expires_at"), out var expiry) && expiry.ToUniversalTime() <= DateTime.UtcNow) return "期限切れ";
        return "有効";
    }
    private void SetStatus(string text, bool error = false) { if (InvokeRequired) { BeginInvoke(() => SetStatus(text, error)); return; } status.Text = text; status.ForeColor = error ? Color.Firebrick : Color.DimGray; }

    private sealed record TenantChoice(string Id, string Display);
    private sealed record TenantOpsRow(string Id, string ParentTenantId, string Slug, string Name, string Status, string Plan, string Environment, string Products, string Licenses, string ActiveApiClients, string MaxProducts, string MaxLicenses, string CreatedAt, string UpdatedAt);
    private sealed record LicenseRow(string Id, string TenantId, string Tenant, string ProductId, string Product, string Label, string State, string ActiveSessions, string ExpiresAt, string Active);
    private sealed record AuditRow(string CreatedAt, string Event, string TargetType, string TargetId, string Role, string Server, string ActorHash, string Change);
    private sealed record ApiKeyRow(string Id, string TenantId, string Tenant, string Name, string Prefix, string Scopes, string Status, string LastUsed, string ExpiresAt, string RevokedAt);
    private sealed record AdminRow(string Id, string Name, string Role, string LastLogin);
}

internal sealed class DesktopCallback : IDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly TaskCompletionSource<string> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim clientSlots = new(8, 8);
    private bool disposed;
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

    public DesktopCallback() { listener.Start(4); _ = AcceptLoopAsync(); }

    public async Task<string> WaitAsync(string state, TimeSpan timeout)
    {
        using var cancel = new CancellationTokenSource(timeout);
        var accepted = await completion.Task.WaitAsync(cancel.Token);
        var parts = accepted.Split('\n', 2);
        if (parts.Length != 2 || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(parts[1]), Encoding.UTF8.GetBytes(state))) throw new InvalidOperationException("SSO応答を照合できませんでした。");
        return parts[0];
    }

    private async Task AcceptLoopAsync()
    {
        while (!disposed && !completion.Task.IsCompleted)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(); }
            catch { return; }
            if (!clientSlots.Wait(0)) { client.Dispose(); continue; }
            _ = HandleClientAsync(client);
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        try
        {
            using (client)
            {
                using var readTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var stream = client.GetStream();
                var bytes = new List<byte>(4096);
                var buffer = new byte[4096];
                var headerEnd = -1;
                while (headerEnd < 0 && bytes.Count < 32768)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(), readTimeout.Token);
                    if (read == 0) return;
                    bytes.AddRange(buffer.AsSpan(0, read).ToArray());
                    headerEnd = FindHeaderEnd(bytes);
                }
                if (headerEnd < 0) { await SendAsync(stream, 400, "text/plain", "Bad Request"); return; }
                var header = Encoding.ASCII.GetString(bytes.Take(headerEnd).ToArray());
                var firstLine = header.Split("\r\n", 2)[0].Split(' ');
                if (firstLine.Length < 2) { await SendAsync(stream, 400, "text/plain", "Bad Request"); return; }
                var method = firstLine[0];
                var path = firstLine[1];
                var lengthLine = header.Split("\r\n").FirstOrDefault(x => x.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                var length = 0;
                if (lengthLine is not null && !int.TryParse(lengthLine.Split(':', 2)[1].Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out length))
                { await SendAsync(stream, 400, "text/plain", "Bad Request"); return; }
                if (length > 16384) { await SendAsync(stream, 413, "text/plain", "Too Large"); return; }
                var bodyOffset = headerEnd + 4;
                while (bytes.Count - bodyOffset < length)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(), readTimeout.Token);
                    if (read == 0) return;
                    bytes.AddRange(buffer.AsSpan(0, read).ToArray());
                }
                if (method == "GET" && path.Split('?', 2)[0] == "/callback")
                {
                    var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
                    var html = "<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer><title>TUTI Operations</title><p>SSO認証を確認しています…</p><script nonce='" + nonce + "'>const p=new URLSearchParams(location.hash.slice(1));const session=p.get('session'),state=p.get('state');history.replaceState(null,'','/callback');if(!session||!state){document.body.textContent='SSO応答を受け取れませんでした。アプリに戻ってやり直してください。'}else fetch('/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session,state})}).then(r=>r.ok?document.body.textContent='ログイン完了。アプリに戻ってください。':document.body.textContent='SSO応答を確認できません。アプリに戻ってやり直してください。').catch(()=>document.body.textContent='アプリへの接続に失敗しました。アプリを確認してください.');</script>";
                    await SendAsync(stream, 200, "text/html; charset=utf-8", html, $"Content-Security-Policy: default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'\r\n");
                    return;
                }
                if (method == "POST" && path == "/complete")
                {
                    using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(bytes.Skip(bodyOffset).Take(length).ToArray()));
                    var token = doc.RootElement.GetProperty("session").GetString() ?? "";
                    var state = doc.RootElement.GetProperty("state").GetString() ?? "";
                    if (token.Length is < 40 or > 8192 || !token.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.') || !System.Text.RegularExpressions.Regex.IsMatch(state, "^[a-f0-9]{64}$"))
                    { await SendAsync(stream, 400, "text/plain", "Invalid response"); return; }
                    await SendAsync(stream, 200, "application/json", "{\"ok\":true}");
                    if (!completion.Task.IsCompleted) completion.TrySetResult(token + "\n" + state);
                    return;
                }
                await SendAsync(stream, 404, "text/plain", "Not Found");
            }
        }
        catch { }
        finally { clientSlots.Release(); }
    }

    private static int FindHeaderEnd(List<byte> bytes)
    {
        for (var i = 3; i < bytes.Count; i++) if (bytes[i - 3] == 13 && bytes[i - 2] == 10 && bytes[i - 1] == 13 && bytes[i] == 10) return i - 3;
        return -1;
    }

    private static async Task SendAsync(NetworkStream stream, int code, string type, string body, string extra = "")
    {
        var payload = Encoding.UTF8.GetBytes(body);
        var headers = $"HTTP/1.1 {code} {Reason(code)}\r\nContent-Type: {type}\r\nContent-Length: {payload.Length}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n{extra}\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(headers));
        await stream.WriteAsync(payload);
        await stream.FlushAsync();
    }
    private static string Reason(int status) => status switch { 200 => "OK", 400 => "Bad Request", 404 => "Not Found", 413 => "Content Too Large", _ => "Error" };
    public void Dispose() { disposed = true; try { listener.Stop(); } catch { } }
}
