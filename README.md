# Daemonchild
A monstrous union of ReactPHP &amp; Drupal 7, inspired by https://github.com/bertrama/php-pm-drupal-seven/issues/6

1. Use FreeBSD 10.3.
2. Use Drupal 7 with the RESTful module 7.x-2.x. Patches are needed to the RESTful module to work with this setup. Open an issue if you are interested in the specific patches needed. It has not been tested with Drupal's native page generation & serving, nor with Drupal/PHp sessions, since I am using RESTful's token authentication sub-module.
3. Add files to the web root of your Drupal 7 installation.
4. Run ```composer install``` from that location. It should install the ReactPHP stack needed for this abomination.
5. Run the shell script with supervisord using the .ini configuration file provided.
6. Put everything behind HAProxy.
7. See the code & the comments in the code for what is going on.
-- 666. ...tse sutan sutsirhC eid eidoH
