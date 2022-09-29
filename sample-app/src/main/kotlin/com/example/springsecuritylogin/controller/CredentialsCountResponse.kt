package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Status

class CredentialsCountResponse(
    val count: Int?,
) : AdapterServerResponse(Status.OK, "") {
    constructor(
        status: Status,
        errorMessage: String,
    ) : this(
        0,
    ) {
        this.status = status
        this.errorMessage = errorMessage
    }
}