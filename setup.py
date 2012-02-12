#!/usr/bin/python

from distutils.core import setup

setup(
    name = 'Mutable Replay',
    author = 'Nicolas Viennot',
    author_email = 'nicolas@viennot.biz',
    packages=['mreplay', 'mreplay.mutator'],
    scripts=['scripts/mreplay', 'scripts/mrecord', 'scripts/isolate'],
    requires=['networkx', 'argparse', 'scribe', 'pygraphviz']
)
