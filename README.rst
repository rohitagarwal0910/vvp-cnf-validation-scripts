VVP CNF Validation Scripts
======================

This repo contains my work done as an intern at Samsung Electronics, South Korea.

This project enhances ONAP's VVP tool to also validate CNFs.
Read about original VVP project `here <https://docs.onap.org/projects/onap-vvp-documentation/en/latest/>`__.

Installation
============

#. `Python 3.6+ <https://www.python.org/downloads/>`__ and `Helm <https://helm.sh/docs/intro/install/>`__ should be installed on your system.
#. (Optional) If desired, you can create a virtual Python environment to avoid installing VVP’s dependencies in your system level installation of Python::

    > python -m venv vvp
    > source vvp/activate
  
#. Run following command to install dependencies.::
  
    python pip install -r requirements.txt

Usage
=====
This tool can be run either from command line or through a GUI

GUI
###
To start the GUI:

#. Navigate to ``ice-validator`` directory::
    
    cd <vvp-directory>/ice-validator
   
#. Execute the script for launching GUI::
  
    python vvp.py

This will launch the VVP tool window. Select CNF package and choose desired settings.
Click on ``Process Templates`` button to start validation. Result will be printed on the right side. Click ``View Report`` button to see test report in HTML, CSV or Excel format as per your choice.

Command line
#########
To validate a CNF package:

#. Navigate to ``ice-validator`` directory::
    
    cd <vvp-directory>/ice-validator

#. Run ``pytest`` command. This will run tests with default settings::
    
    pytest tests-cnf --package-directory=<path-to-package>
   
   Where ``<path-to-package>`` points to location of the CNF package. Both ``.zip`` file and uncompressed directories are supported.

Additional tests can be enabled or disbaled as per wish. Go to ``ice-validator/tests-cnf/optional_tests_setting.yaml`` and set desired tests to ``true``.

Test results will be written to the consoles describing any failures that are encountered. If no failures are found, then a success message will be displayed. Additional report in HTML(default), CSV or Excel format can be found in the <VVP Directory>/ice_validator/output directory.

Following flags are supported to change configuration: ::
   
   --template-directory=<path-to-package>
                      Path to .zip file or directory which holds the package for validation
   
   --optional-tests-setting=<path-to-yaml-file>
                      Alternate file containing settings for additional tests
   
   --output-directory=<path-to-dir>
                      Alternate directory for report output.
   
   --report-format=<format>
                      Format of output report (html, csv, excel, json)
                      
Refer to pytest documentation for flags provided by the library.

*Note: Contents of* ``ice-validator/cnf_requirements.json`` *are not a part of formal specification. That file has been made for enabling listing requirements along with failures in generated reports.*