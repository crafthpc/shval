FROM centos:7
LABEL name="SHVAL"
LABEL maintainer="Mike Lam <lam2mo@jmu.edu>"
LABEL description="Infrastructure for compiling and using the shadow value analysis library (SHVAL)"
LABEL architecture="x86_64"
LABEL version="1.0"

# install necessary software
RUN yum -y update && yum -y install wget git make gcc gcc-c++ gmp-devel mpfr-devel

# top-level folder for installation
ENV ROOTDIR /root

# download and extract Pin
WORKDIR $ROOTDIR/opt
RUN wget http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-gcc.4.4.7-linux.tar.gz && \
    tar xf pin-2.14-71313-gcc.4.4.7-linux.tar.gz && \
    rm pin-2.14-71313-gcc.4.4.7-linux.tar.gz

# clone and build SHVAL
WORKDIR $ROOTDIR/src
RUN git clone https://github.com/lam2mo/shval.git
WORKDIR $ROOTDIR/src/shval/tools
RUN bash build.sh

# install convenience shell script
COPY shval /usr/local/bin/

# run example
WORKDIR $ROOTDIR/src/shval/tests/sum
RUN make
CMD ["shval","native64","--","./main"]

