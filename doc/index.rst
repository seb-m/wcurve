.. wcurve documentation master file, created by
   sphinx-quickstart on Sat Oct  2 11:47:19 2010.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

wcurve
=======

Project URL: http://github.com/seb-m/wcurve

.. toctree::
   :maxdepth: 4

Description
------------

.. automodule:: wcurve


Details
-------

Curves
^^^^^^
.. autofunction:: secp256r1_curve
.. autofunction:: secp256r1_curve_infective
.. autoclass:: _Curve

Class JacobianPoint
^^^^^^^^^^^^^^^^^^^^
.. autoclass:: JacobianPoint
   :members:


References
-----------

.. [1] Co-Z Addition Formulae and Binary Ladders on Elliptic Curves by *Raveen R. Goundar and Marc Joye and Atsuko Miyaji*.
.. [2] Sign Change Fault Attacks On Elliptic Curve Cryptosystems by *Blomer, Otto and Seifert*.
