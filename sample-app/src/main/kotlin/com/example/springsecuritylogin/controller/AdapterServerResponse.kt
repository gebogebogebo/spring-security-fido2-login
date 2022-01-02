package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Status

open class AdapterServerResponse(
    var status: Status,
    var errorMessage: String,
)
