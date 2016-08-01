=======
Butcher
=======
Butcher is a `shmux <http://web.taranis.org/shmux/>`_-based shell for executing commands within Chef-managed infrastructure.

Installation
------------
First, you need to install shmux itself. You may check whether there's a package available for your distribution, or just build it from sources (`latest available release <http://web.taranis.org/shmux/dist/shmux-1.0.2.tgz>`_). 

Butcher itself can be installed via setup.py, like this

.. code:: bash
  
  sudo python setup.py install

Configuration
-------------
Copy `butcherrc_example <https://github.com/beebeeep/butcher/blob/master/butcherrc_example>`_ to ~/.butcherrc and apply your changes

Usage
-----
Just run ``butcher`` and type ``help`` there (first run may take a while due to updating hosts database, later you can use ``butcher -a`` to skip DB update)
