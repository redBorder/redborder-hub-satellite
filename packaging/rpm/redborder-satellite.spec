Name:           redborder-satellite
Version:        %{__version}
Release:        %{__release}%{?dist}
Summary:        Decentralized Spoke Observability Agent (Satellite) for Redborder Hub
License:        MIT
URL:            https://github.com/redborder/satellite

Source0:        redborder-hub-satellite-%{version}.tar.gz

BuildRequires:  golang >= 1.16
BuildRequires:  systemd
Requires:       systemd
Requires:       net-snmp-utils
Requires:       traceroute

# Disable debuginfo package generation since Go binaries don't require standard C debug symbols
%global debug_package %{nil}

%description
A secure, decentralized Hub-and-Spoke satellite written in Go, which maintains outbound
persistent WebSocket connections to the central redborder-hub platform to execute predefined
monitoring jobs like ping and SNMP walks over JSON-RPC.

%prep
%setup -qn redborder-hub-satellite-%{version}

%build
# Compile the satellite binary
go build -ldflags="-w -s" -o bin/redborder-satellite cmd/agent/main.go

%install
# Create target installation directories
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/%{name}
install -d %{buildroot}%{_unitdir}

# Copy files to their buildroot destinations
install -p -m 0755 bin/redborder-satellite %{buildroot}%{_bindir}/redborder-satellite
install -p -m 0640 packaging/satellite.json.example %{buildroot}%{_sysconfdir}/%{name}/satellite.json
install -p -m 0644 packaging/redborder-satellite.service %{buildroot}%{_unitdir}/redborder-satellite.service

%post
%systemd_post redborder-satellite.service

%preun
%systemd_preun redborder-satellite.service

%postun
%systemd_postun_with_restart redborder-satellite.service

%files
%{_bindir}/redborder-satellite
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/satellite.json
%{_unitdir}/redborder-satellite.service

%changelog
* Fri Jul 17 2026 Redborder Maintainers - 1.0.0-1
- Initial RPM release of redborder-satellite.
