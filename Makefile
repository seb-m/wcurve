PYTHON=python

test:
	cd tests; \
	$(PYTHON) setup.py build; \
	$(PYTHON) wcurve_unittest.py

clean:
	rm -rf dist build tests/build MANIFEST
	find . \( -name '*~' -or \
		-name '*.pyc' -or \
		-name '*.pyo' -or \
		-name '#*' -or \
		-name '*.so' \) \
		-print -exec rm {} \;
