Name:           dm-xor-dkms
Version:        1.2.0
Release:        1%{?dist}
Summary:        Device-mapper XOR split kernel module (DKMS)

License:        GPL-2.0+
URL:            https://github.com/luis-javier-gonzalez-alonso/dm-xor
Source0:        https://github.com/luis-javier-gonzalez-alonso/dm-xor/archive/v%{version}/dm-xor-%{version}.tar.gz

BuildArch:      noarch
Requires:       dkms
Requires:       kernel-devel

%description
Device-mapper target that XOR-splits data across N disks for data security
through redundant encoding. This package provides the kernel module sources
and integrates with DKMS so the module is automatically built for each kernel.

%prep
%autosetup -n dm-xor-%{version}

%build
# Nothing to build – DKMS will compile the module for the running kernel.

%install
install -d %{buildroot}%{_usrsrc}/dm-xor-%{version}/
install -m 0644 dm_xor_split.c  %{buildroot}%{_usrsrc}/dm-xor-%{version}/
install -m 0644 xor_core.c      %{buildroot}%{_usrsrc}/dm-xor-%{version}/
install -m 0644 xor_core.h      %{buildroot}%{_usrsrc}/dm-xor-%{version}/
install -m 0644 Makefile         %{buildroot}%{_usrsrc}/dm-xor-%{version}/
install -m 0644 dkms.conf        %{buildroot}%{_usrsrc}/dm-xor-%{version}/

%post
dkms add     -m dm-xor -v %{version} --rpm_safe_upgrade
dkms build   -m dm-xor -v %{version}
dkms install -m dm-xor -v %{version}

%preun
dkms remove  -m dm-xor -v %{version} --all --rpm_safe_upgrade || :

%files
%{_usrsrc}/dm-xor-%{version}/

%changelog
* Sun Jun 08 2026 Luis Javier González Alonso <luis.javier.gonzalez.alonso@gmail.com> - 1.2.0-1
- Initial DKMS package for dm-xor kernel module
