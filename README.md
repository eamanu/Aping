# Aping

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Open Source Love png1](https://badges.frapsoft.com/os/v1/open-source.png?v=103)]()
[![Generic badge](https://img.shields.io/badge/Version-0.1_Beta_4.post1-green.svg)](https://shields.io/)

Aping (Advanced ping program) is a network ping utility written entirely in the Python programming language, which in addition to the standard ping program can execute four types of ICMP probes (pings): echo request (the standard ping), timestamp request, address mask request, and information request.

Aping was initially written by Kantor A. Zsolt <kantorzsolt@yahoo.com>. This is a project that started in 2007. In 2018 was Overtaken and maintained by Emmanuel Arias <emmanuelarias30@gmail.com>

The project homepage is: http://www.nongnu.org/aping

Development webpage is: https://savannah.nongnu.org/projects/Aping


## Readme file for Aping

The program license is described in COPYING
The program documentation license is described in COPYING-DOCS

## REQUIREMENTS:

Some kind of GNU/Linux distribution
Python version 2.3 or higher installed (the C implementation)

## INSTALLATION:

If you read this I think you have already extracted the tarball. Aping needs no
additional installation or configuration, just download, extract and run it from
a terminal.

### INSTALLATION via setup.py or pip

You can install aping doing:
    
    git clone https://github.com/eamanu/Aping/Aping.py
    cd Aping.py
    python setup.py install
 
 or via pip:
 
    pip install ApingTool

## USAGE:

Aping is a non-interactive command line interface application. So you must to 
use Aping options to talk with the program. Open a terminal/shell go in the
directory where Aping was extracted and for a list of options use the -h or     
--help commands (eg. ./aping.py --help), or enter in the manual directory and 
type: man ./Aping.1 to see a more detailed description of the options 

### New Usage

If you install Aping via pip or setup.py you can just run:

    sudo ping aping 8.8.8.8

## CONTACT:   

If you have some comments, suggestions or a patch send to: 
The author personal e-mail address: kantorzsolt@yahoo.com
or
The maintainer personal e-mail address: emmanuelarias30@gmail.com

## TODO LIST

Please, take a look at TODO.md file

## Contribution

Please, read [CONTRIBUTING.md](https://github.com/eamanu/Aping/blob/master/CONTRIBUTING.md) for contributions. 

Thanks!
