% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_sas_new}
\alias{mxc_sas_new}
\title{Create an ephemeral Matrix SAS key agreement}
\usage{
mxc_sas_new()
}
\value{
An opaque SAS handle.
}
\description{
Wraps vodozemac's short-authentication-string key agreement. The handle
cannot be saved or restored; restart interrupted verification with a new
transaction and handle. Protocol negotiation, commitments, user prompts,
timeouts, and cross-signing policy belong to mx.client.
}
