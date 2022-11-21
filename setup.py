
from setuptools import setup, find_packages


setup(
    name='snort_web_master',
    version='0.1',
    license='MoCorp',
    author="meir dahan",
    author_email='1dahanmeir1@gmail.com',
    packages=find_packages('snort_web_master'),
    package_dir={'': 'snort_web_master'},
    url='https://github.com/mosheovadi1/snort-web-master',
    keywords='snort3 django',
    install_requires=[
          'django',
'django-auth-ldap==1.7.0',
'django-object-actions','dpkt',

      ],

)