help:
	@echo "  clean       remove artifacts from running python setup.py install"
	@echo "  archive     creates tar.gz of this project"
	@echo "  package     creates a python package for distribution"

clean:
	rm -Rf mininet-topology.egg-info && \
	rm -Rf build *.egg-info dist && \
	rm -Rf ChangeLog && \
	rm -Rf AUTHORS

archive:
	make clean && \
	tar -zcvf ./flow-manager-tools.tar.gz --exclude='.git' --exclude='.env' --exclude='.venv' --exclude='flow-manager-tools.tar.gz' -C .. ./flow-manager-tools

package:
	make clean && \
	python setup.py sdist bdist_wheel
