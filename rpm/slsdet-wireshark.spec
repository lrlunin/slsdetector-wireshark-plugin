# RPM of the prebuilt plugin (ci/build.sh output) for the distribution's own
# Wireshark. Wireshark only loads plugins built for its major.minor, so the
# package pins wireshark-cli to that release line.
#
#   rpmbuild -bb rpm/slsdet-wireshark.spec \
#     --define "_sourcedir $PWD/dist" \
#     --define "plugin_version 1.0.0" \
#     --define "ws_line 2.6" \
#     --define "ws_epoch 1"
#
# _sourcedir must hold slsdet.so and README.md.

%{!?plugin_version: %global plugin_version 1.0.0}
%{!?plugin_release: %global plugin_release 1}
%{!?ws_line:  %{error:ws_line (Wireshark major.minor) must be defined}}
%{!?ws_epoch: %global ws_epoch 0}
%global ws_next %(echo %{ws_line} | awk -F. '{ print $1 "." $2 + 1 }')
%global plugin_dir %{_libdir}/wireshark/plugins/%{ws_line}/epan

# stripped prebuilt binary: nothing to extract or link
%global debug_package %{nil}
%global _build_id_links none

Name:           slsdet-wireshark
Version:        %{plugin_version}
Release:        %{plugin_release}%{?dist}
Summary:        Wireshark dissector for SLS detector UDP packets
License:        Unspecified
URL:            https://github.com/slsdetectorgroup/slsdetector-wireshark-plugin
Source0:        slsdet.so
Source1:        README.md
ExclusiveArch:  x86_64

Requires:       (wireshark-cli >= %{ws_epoch}:%{ws_line} with wireshark-cli < %{ws_epoch}:%{ws_next})

%description
Wireshark plugin that decodes the 48-byte sls_detector_header of
slsDetectorPackage UDP packets (Jungfrau, Moench, Eiger, Mythen3, ...).
Built for Wireshark %{ws_line}.

%prep

%build

%install
install -D -m 0755 %{SOURCE0} %{buildroot}%{plugin_dir}/slsdet.so
install -D -m 0644 %{SOURCE1} %{buildroot}%{_docdir}/%{name}/README.md

%files
%{plugin_dir}/slsdet.so
%doc %{_docdir}/%{name}/README.md
