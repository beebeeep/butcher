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
First run of ``butcher`` may take some time as it fetches hosts information from Chef servers you configured in ~/.butcherrc. After that, you can start it with -a parameter, i.e ``butcher -a`` to use cached data (this data is periodically upgrading in background while butcher is running). 

Once you get into butcher shell, your current environment, region and user will be displayed in prompt string. Environments are chef servers you configured, you are always working within specific environment i.e with single Chef server. Regions are actual Chef environments, you can select specific one with ``region`` command or say ``unset region`` to use all. User is actualy user that will be used for ssh-ing to hosts, can be changed with command ``set user`` or reseted to current user using ``unset``. 

Main commands are:

  * ``hostlist SELECTOR`` - displays hosts matching SELECTOR
  * ``p_exec SELECTOR CMD`` - executes CMD on hosts matching SELECTOR in parallel (maximum number of threads can be set using ``threads`` commands)
  * ``exec SELECTOR CMD`` - same as ``p_exec``, but sequentially, in one thread. 

SELECTOR is comma-separated list of hosts or expressions like ``%ROLE[@REGION]``, where ROLE is actual chef role (``*`` glob can be used) and REGION is region, i.e. Chef environment (if missing, current region will be used)
