Name:           redborder-hub
Version:        %{__version}
Release:        %{__release}%{?dist}
Summary:        Central Management Hub for Redborder Observability Platform
License:        MIT
URL:            https://github.com/redborder/hub

Source0:        redborder-hub-satellite-%{version}.tar.gz

BuildRequires:  golang >= 1.16
BuildRequires:  systemd
Requires:       systemd

# Define %%{_unitdir} fallback if systemd-rpm-macros is missing
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}

# Disable debuginfo package generation since Go binaries don't require standard C debug symbols
%global debug_package %{nil}

%description
A secure, central management platform written in Go, which coordinates, schedules,
and dispatches JSON-RPC observability jobs to registered remote satellites.

%prep
%setup -qn redborder-hub-satellite-%{version}

%build
# Compile the hub binary
go build -ldflags="-w -s" -o bin/redborder-hub cmd/hub/main.go

%install
# Create target installation directories
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/%{name}
install -d %{buildroot}%{_sysconfdir}/%{name}/authorized_keys
install -d %{buildroot}%{_unitdir}

# Copy files to their buildroot destinations
install -p -m 0755 bin/redborder-hub %{buildroot}%{_bindir}/redborder-hub
install -p -m 0640 packaging/hub.json.example %{buildroot}%{_sysconfdir}/%{name}/hub.json
install -p -m 0644 packaging/redborder-hub.service %{buildroot}%{_unitdir}/redborder-hub.service

%pre
getent group %{name} >/dev/null || groupadd -r %{name}
getent passwd %{name} >/dev/null || \
    useradd -r -g %{name} -d / -s /sbin/nologin \
    -c "User of %{name} service" %{name}
exit 0

%post
# Generate a unique auth token when the config still holds a placeholder or
# the legacy well-known default. A real token is never touched.
HUB_CONF=%{_sysconfdir}/%{name}/hub.json
if [ -f "$HUB_CONF" ] && grep -Eq '"auth_token"[[:space:]]*:[[:space:]]*"(CHANGE_ME|super-secret-agent-token)"' "$HUB_CONF"; then
    HUB_TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    if [ ${#HUB_TOKEN} -eq 64 ]; then
        sed -i -E "s/(\"auth_token\"[[:space:]]*:[[:space:]]*\")(CHANGE_ME|super-secret-agent-token)(\")/\1${HUB_TOKEN}\3/" "$HUB_CONF"
        echo "redborder-hub: generated a unique auth_token in $HUB_CONF." >&2
        echo "redborder-hub: copy it to every other hub of the cluster and use it to register satellites." >&2
    else
        echo "redborder-hub: could not generate an auth_token; set it manually in $HUB_CONF." >&2
    fi
    unset HUB_TOKEN
fi
%systemd_post redborder-hub.service

%preun
%systemd_preun redborder-hub.service

%postun
%systemd_postun_with_restart redborder-hub.service

%files
%{_bindir}/redborder-hub
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/authorized_keys
%config(noreplace) %{_sysconfdir}/%{name}/hub.json
%{_unitdir}/redborder-hub.service

%changelog
* Fri Jul 17 2026 David Vanhoucke <dvanhoucke@redborder.com> - 1.0.0-1
- Initial RPM release of redborder-hub.
