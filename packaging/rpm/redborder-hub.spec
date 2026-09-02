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
