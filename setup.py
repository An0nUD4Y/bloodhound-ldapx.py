from setuptools import setup

setup(name='bloodhound-ce-ldapx',
      version='1.9.1',
      description='Python based ingestor for BloodHound Community Edition',
      author='Dirk-jan Mollema, Edwin van Vliet, Matthijs Gielen',
      author_email='dirkjan@dirkjanm.io, edwin.vanvliet@fox-it.com, matthijs.gielen@fox-it.com',
      maintainer='Dirk-jan Mollema',
      maintainer_email='dirkjan@dirkjanm.io',
      url='https://github.com/An0nUD4Y/bloodhound-ldapx.py',
      packages=['bloodhound',
                'bloodhound.ad',
                'bloodhound.lib',
                'bloodhound.enumeration'],
      license='MIT',
      python_requires='>=3.9',
      install_requires=['dnspython', 'impacket>=0.9.17', 'ldap3>=2.5,!=2.5.2,!=2.5.0,!=2.6',
                        'ldap3-ad-auth>=0.1.0', 'ldapx>=0.5.0', 'pyasn1>=0.4',
                        'pycryptodome', 'PySocks'],
      classifiers=[
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
      ],
      entry_points= {
        'console_scripts': ['bloodhound-ce-ldapx=bloodhound:main']
      }
      )
