# CPE Validation Report

Validation of CPE values from `packageDBdata.csv` against NVD (National Vulnerability Database).

## Summary

| Status | Count |
|--------|-------|
| Valid | 62 |
| Invalid/Wrong | 5 |
| Questionable | 3 |

## Invalid/Problematic CPEs

| Package | Test CPE | Issue | Correct CPE |
|---------|----------|-------|-------------|
| gps_daemon | berlios:gps_daemon | OBSOLETE: berlios.de is defunct. NVD uses gpsd_project:gpsd (94 records) | gpsd_project:gpsd |
| fwtool | fwtool:fwtool | UNVERIFIED: No NVD records found - may be OpenWrt-specific tool | N/A |
| ipset | ipset:ipset | INVALID: Vendor should be "netfilter" not "ipset" | netfilter:ipset |
| libedit | libedit_project:libedit | QUESTIONABLE: NVD may use thrysoee:libedit (author name) instead | thrysoee:libedit |
| liblz4 | lz4_project:liblz4 | INVALID: Product should be "lz4" not "liblz4" | lz4_project:lz4 |
| liblzo | lzo_project:liblzo | QUESTIONABLE: NVD uses oberhumer:lzo (author/company name) | oberhumer:lzo |
| libcap | tcpdump:libpcap | WRONG_PACKAGE: Test file has WRONG CPE! libcap != libpcap | libcap_project:libcap |
| terminfo | terminfo:ncurses | INVALID: Vendor "terminfo" not valid. Should be gnu:ncurses | gnu:ncurses |

## Critical Errors

### 1. libcap vs libpcap confusion
The test file has `libcap` with CPE `tcpdump:libpcap` - this is **completely wrong**:
- `libcap` = Linux capabilities library → `cpe:2.3:a:libcap_project:libcap`
- `libpcap` = Packet capture library → `cpe:2.3:a:tcpdump:libpcap`

These are entirely different packages!

### 2. Obsolete vendor: berlios
`berlios:gps_daemon` - BerliOS was a software hosting site that shut down in 2014.
The gpsd project is now tracked as `gpsd_project:gpsd` in NVD (94 records).

### 3. Wrong vendor for ncurses
`terminfo:ncurses` - There is no vendor 'terminfo' in NVD.
The correct CPE is `gnu:ncurses` (21 records in NVD).

## NVD Verification Sources

The following CPEs were verified against the NVD CPE Dictionary:

- [attr_project:attr](https://nvd.nist.gov/products/cpe/search/results?keyword=cpe:2.3:a:attr_project:attr) - Valid
- [gnu:ncurses](https://nvd.nist.gov/products/cpe/search/results?keyword=cpe:2.3:a:gnu:ncurses) - 21 records
- [gpsd_project:gpsd](https://nvd.nist.gov/products/cpe/search/results?keyword=cpe:2.3:a:gpsd_project:gpsd) - 94 records
- [samba:ppp](https://nvd.nist.gov/products/cpe/search/results?keyword=cpe:2.3:a:samba:ppp) - 58 records
- [tcpdump:libpcap](https://nvd.nist.gov/products/cpe/search/results?keyword=cpe:2.3:a:tcpdump:libpcap) - 41 records
- [libcap_project:libcap](https://nvd.nist.gov/products/cpe/search/results?keyword=cpe:2.3:a:libcap_project:libcap) - 69 records
- [lz4_project:lz4](https://nvd.nist.gov/products/cpe/search/results?keyword=cpe:2.3:a:lz4_project:lz4) - Valid

## Recommendations

1. **Do not trust the test data CPEs blindly** - Several have errors
2. **Use the SBOM CPEs** - They appear to be more accurate based on NVD validation
3. **Add missing CPEs to KNOWN_METADATA** - For packages like `libcap-ng`, `libdaemon`, `libnl`, `libpopt`, `libqrencode` that have valid NVD CPEs but are missing from the SBOM
