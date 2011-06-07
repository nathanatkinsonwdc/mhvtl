# Copyright 1999-2010 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header:

EAPI="2"

inherit linux-mod eutils

#MY_P="${PN}-2010-07-09"
MY_P="${PN}-2011-05-22"
DESCRIPTION="mhvtl module provides Virtual (SCSI) Tape Library"
HOMEPAGE="http://sites.google.com/site/linuxvtl2"
SRC_URI="http://sites.google.com/site/linuxvtl2/${MY_P}.tgz"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="doc"

DEPEND=">=virtual/linux-sources-2.6.19
		sys-fs/lsscsi
		sys-libs/zlib
		sys-apps/sg3_utils"
RDEPEND=""

MODULE_NAMES="mhvtl(block:${S}/kernel:${S}/kernel)"
BUILD_TARGETS="clean default"
MHVTL_HOME_PATH=/var/spool/media/vtl
LUSER='vtl'
LGROUP='vtl'

pkg_setup() {
	enewgroup ${LGROUP}
	enewuser ${LUSER} -1 -1 ${MHVTL_HOME_PATH} "${LGROUP},tape"

	CONFIG_CHECK="~BLK_DEV_SR ~CHR_DEV_SG"
	check_extra_config
	BUILD_PARAMS="KDIR=${KV_DIR}"
	linux-mod_pkg_setup
}

src_prepare() {
	epatch "${FILESDIR}/0.18-kerneldir.patch"
	epatch "${FILESDIR}/0.18-etc.patch"
	epatch "${FILESDIR}/0.18-make_vtl_media.patch"
	epatch "${FILESDIR}/0.18-mhvtl.patch"
}

src_compile() {
	emake clean || die
	linux-mod_src_compile || die "linux-mod_src_compile"
	emake USR=${LUSER} GROUP=${LGROUP} MHVTL_HOME_PATH=${MHVTL_HOME_PATH} || die "emake failed"
}

src_install() {
	linux-mod_src_install || die "Error: installing module failed!"

	emake USR=${LUSER} GROUP=${LGROUP} MHVTL_HOME_PATH=${MHVTL_HOME_PATH} DESTDIR=${D} install || die "emake failed"

	einfo "Generating udev rules ..."
	dodir /etc/udev/rules.d/
	cat > "${D}"/etc/udev/rules.d/70-mhvtl.rules <<-EOF || die
	# do not edit this file, it will be overwritten on update
	#
	KERNEL=="mhvtl[0-9]*", MODE="0660", OWNER="vtl", GROUP="vtl"
	EOF

	newinitd "${FILESDIR}"/mhvtl.init.d mhvtl || die

	if use doc; then
		dohtml -r doc/* || die
	fi

	doman man/*.1 || die
	dodoc README INSTALL
}

pkg_postinst() {
	linux-mod_pkg_postinst
}
