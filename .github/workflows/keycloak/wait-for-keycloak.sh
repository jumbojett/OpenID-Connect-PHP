#/bin/bash

set -e

if [ -z "${1}" ]
then
  echo "Url is empty"
  exit 1
fi

maxcounter=${2:-60}
counter=1

# Try to access url
# If we can not access it sleep for 1 sec
while [[ "$(curl -s -o /dev/null -m 3 -L -w ''%{http_code}'' ${1})" == "000" ]]; do
  if [ ${counter} -eq ${maxcounter} ]
  then
    echo "Max counter reached"
    exit 1
  fi

  >&2 echo "${1} - sleeping"
  sleep 2
  ((counter++))
done

>&2 echo "${1} - ok"