EPYDOC=epydoc
DSTDOC=docstrings

doc: clean-doc
	$(EPYDOC) --html --graph=all -v -o $(DSTDOC) wcurve.py

clean-doc:
	rm -rf $(DSTDOC)

clean: clean-doc
	rm -rf dist
	find . \( -name '*~' -or \
		-name '*.pyc' -or \
		-name '*.pyo' \) \
		-print -exec rm {} \;
