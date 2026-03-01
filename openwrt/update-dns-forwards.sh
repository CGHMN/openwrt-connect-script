#!/bin/ash
# Downloads DNS forwards in dnsmasq configuration file format to point domains available
# on the CGHMN towards our primary DNS server, see the Wiki entry below for more info:
# https://wiki.cursedsilicon.net/index.php?title=CGHMN_DNS_Information#dnsmasq_Synchronization_Script

set -e

# setting static variables
SRC_URL="http://100.64.12.1:8080/dns-forward-domains.dnsmasq.conf"
CONF_FILE=/etc/cghmn-domains.dnsmasq.conf
TMP_CONF_FILE=/tmp/cghmn-domains.dnsmasq.conf

# optional, set this to a file where each line is a domain that shall be
# excluded from the downloaded domain list. If followed by a slash (/),
# only domains that end in the specified string are skipped, if starting
# with a slash, all domains starting with tthe specified string are filtered.
# Otherwise, all domains which contain the specified string are filtered.
#
# Example:
# 
# adobe.com/
# windowsupdate
# /aim
#
# The two lines above would filter all domains that *end* with adobe.com,
# so both adobe.com but also e.g. activate.adobe.com would not be configured
# to point to the CGHMN DNS resolver. However, something like adobe.retro
# would still be forwarded to the CGHMN resolver. The second line would
# filter all domains overrides out that contain 'windowsupdate' anywhere in
# them, so both windowsupdate.com and windowsupdate.microsoft.com would
# not get forwarded to the CGHMN. The last line would filter all domains
# which start with 'aim', so e.g. aim-charts.pf.aol.com and aimtoday.aol.com
# are filtered out, but www.aim.com would still get overriden.
# If this variable is not set or the file is not readable, the downloaded file
# will be passed to dnsmasq unfiltered.
DOMAIN_FILTER_FILE="/etc/cghmn-domains.filter"

# download dns configuration to temporary location and get its md5 sum
if ! wget -qO "${TMP_CONF_FILE}" "${SRC_URL}"; then
        echo "Failed to download the dnsmasq domain list" >&2
        exit 1
fi

# apply filter file if specified
if [ "${DOMAIN_FILTER_FILE:-}" ] && [ -r "${DOMAIN_FILTER_FILE}" ]; then
        grep -vf "${DOMAIN_FILTER_FILE}" "${TMP_CONF_FILE}" > "${TMP_CONF_FILE}.filtered"
        mv "${TMP_CONF_FILE}.filtered" "${TMP_CONF_FILE}"
fi

# get md5 sums of files
old_md5sum="$(md5sum -- "${CONF_FILE}" | cut -d' ' -f1)"
new_md5sum="$(md5sum -- "${TMP_CONF_FILE}" | cut -d' ' -f1)"

# do nothing if the md5sum of the new file is the same as the old file
if [ "${old_md5sum}" = "${new_md5sum}" ]; then
        exit 0
fi

# test if configuration file is valid
if ! dnsmasq -C "${TMP_CONF_FILE}" --test &>/dev/null; then
        echo "New dnsmsq DNS configuration for the CGHMN is invalid" >*2
        exit 1
fi

# copy configuration file to permanent location
cp "${TMP_CONF_FILE}" "${CONF_FILE}"

# restart dnsmasq service on changes
service dnsmasq restart
