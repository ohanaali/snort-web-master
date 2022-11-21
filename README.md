# snort-web-master
### This is a simple package designed to manage snort3 rule in a private repo. in order to allow internal user to write their own snort sigs.
### <b> it is highly recomended  to replace the development db exists in this package</b> 


if you decede not to:
## This is the default password for the users in the db:
snort-master: snort1234 <br>
simple:Ss123456 <br>


# open issues:
### todo: active directory sync users
### todo: fix the sig structure


# instalation

make sure to have  <b> ciscotalos/snort3 </b> docker image avaliable

```
cd to this directory
```
```
docker build -t snort-web-master -f snortFile .
docker run -p 8000:8000 -t snort-web-master   
```
