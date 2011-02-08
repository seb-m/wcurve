# 'make test' to run tests
# 'make example' to run examples
# 'make clean' to clean-up

test:
	cd tests; \
	./run.sh;

example:
	cd examples; \
	./run.sh;

clean:
	rm -rf dist build tests/build MANIFEST docs/_build
	find . \( -name '*~' -or \
		-name '*.pyc' -or \
		-name '*.pyo' -or \
		-name '#*' -or \
		-name '*.so' \) \
		-print -exec rm {} \;
