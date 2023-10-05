FROM	quay.io/pypa/manylinux_2_28_x86_64

RUN	yum install -y keyutils-libs-devel
RUN	<<-EOF
	python_versions=("38" "39" "310" "311")
	for version in "${python_versions[@]}"; do
		PYBIN="/opt/python/cp$version-cp$version/bin"
		"${PYBIN}/pip" install cython
	done
EOF

COPY	buildwheels.sh /bin/
ENTRYPOINT ["/bin/buildwheels.sh"]
CMD	["manylinux_2_28_x86_64"]
