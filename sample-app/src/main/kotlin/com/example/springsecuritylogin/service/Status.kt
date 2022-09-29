package com.example.springsecuritylogin.service

import com.fasterxml.jackson.annotation.JsonValue

enum class Status(@JsonValue val value: String) {
    OK("ok"),
    FAILED("failed"),
}
