% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_sas_bytes}
\alias{mxc_sas_bytes}
\title{Derive the six Matrix SAS display bytes}
\usage{
mxc_sas_bytes(sas, info)
}
\arguments{
\item{sas}{An established SAS handle.}

\item{info}{The protocol's ordered SAS context string.}
}
\value{
A raw vector of length six, for decimal or emoji presentation.
}
\description{
Derive the six Matrix SAS display bytes
}
