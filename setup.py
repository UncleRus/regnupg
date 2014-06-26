from distutils.core import setup

from regnupg import __version__ as version

setup (
    name = 'regnupg',
    description = 'A wrapper for the Gnu Privacy Guard (GPG or GnuPG)',
    long_description = open ('README.md').read (),
    license = 'LGPLv3',
    version = version,
    author = 'Ruslan V. Uss',
    author_email = 'unclerus@gmail.com',
    maintainer = 'Ruslan V. Uss',
    maintainer_email = 'unclerus@gmail.com',
    py_modules = ['regnupg'],
    data_files = [('', ['LICENSE.txt', 'README.md'])],
    platforms = 'No particular restrictions',
    url = 'https://github.com/UncleRus/regnupg',
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2.4',
        'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.1',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
