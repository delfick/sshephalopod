#!/bin/bash

if ! which virtualenv 2>&1 > /dev/null; then
  echo "Please install virtualenv and then run this"
  exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TMP_DIR="$DIR/.tests"
if [[ ! -d $TMP_DIR ]]; then
  opts=""
  if [[ -f /usr/bin/python2.7 ]]; then
    question="
import sys
if sys.version.startswith('2.7'): sys.exit(1)
    "
    if python -c "$question"; then
      opts=" -p /usr/bin/python2.7"
    fi
  fi

  if ! virtualenv $opts $TMP_DIR; then
    echo "Couldn't make the virtualenv :("
    rm -rf $TMP_DIR
    exit 1
  fi
fi

source $TMP_DIR/bin/activate
if [[ -z $IGNORE_PIP ]]; then
	pip install pip --upgrade
	pip install -r $DIR/test_requirements.txt
fi

(
  cd $DIR
  nosetests --with-noy "$@"
)

