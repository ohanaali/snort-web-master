
from setuptools import setup, find_packages


setup(
    name='snort_web_master',
    version='0.1.0.3',
    license='MoCorp',
    author="meir dahan",
    author_email='1dahanmeir1@gmail.com',
    packages=find_packages('snort_web_master'),
    package_dir={'': 'snort_web_master'},
    url='https://github.com/mosheovadi1/snort-web-master',
    keywords='snort3 django',
    include_package_data=False,
    install_requires=[
          'django',
'django-auth-ldap3-ad',
'django-object-actions','dpkt',

      ],

)