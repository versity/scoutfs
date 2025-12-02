
ARG IMAGE_SOURCE=library/centos:centos7.9.2009
FROM "${IMAGE_SOURCE}"
ARG PUB_OR_VAULT=pub
ENV PUB_OR_VAULT=${PUB_OR_VAULT}
ARG HTTP_PROXY=http://package-mirror.vpn.versity.com:3128
ENV HTTP_PROXY=${HTTP_PROXY}
ARG http_proxy=http://package-mirror.vpn.versity.com:3128
ENV http_proxy=${http_proxy}
ARG SKIP_REPO_FIXUP=false
ENV SKIP_REPO_FIXUP=${SKIP_REPO_FIXUP}

COPY repo-fixup.sh /tmp/repo-fixup.sh
RUN PUB_OR_VAULT="${PUB_OR_VAULT}" bash /tmp/repo-fixup.sh
RUN bash -c "yum install -y diff || yum install -y diffutils"
RUN yum groupinstall -y 'Development Tools'
RUN yum install -y epel-release rpm-build sudo
RUN yum install -y mock

