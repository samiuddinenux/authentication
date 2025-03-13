package com.eunx.auth.dto;

public class ApiResponse<T> {
    private boolean success;
    private T data;
    private String message;
    private int status;

    // Success response
    public ApiResponse(T data, String message, int status) {
        this.success = true;
        this.data = data;
        this.message = message;
        this.status = status;
    }

    // Error response
    public ApiResponse(String message, int status) {
        this.success = false;
        this.data = null;
        this.message = message;
        this.status = status;
    }

    // Getters and setters
    public boolean isSuccess() { return success; }
    public T getData() { return data; }
    public String getMessage() { return message; }
    public int getStatus() { return status; }
}