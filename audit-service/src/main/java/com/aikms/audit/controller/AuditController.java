package com.aikms.audit.controller;

import com.aikms.audit.domain.AuditLog;
import com.aikms.audit.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    @GetMapping("/namespaces/{namespaceId}")
    @PreAuthorize("hasAnyAuthority('AUDITOR','SECURITY_ADMIN','SUPER_ADMIN')")
    public Page<AuditLog> getByNamespace(
            @PathVariable String namespaceId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @PageableDefault(size = 50) Pageable pageable) {

        if (from != null && to != null) {
            return auditLogRepository.findByNamespaceAndPeriod(namespaceId, from, to, pageable);
        }
        return auditLogRepository.findByNamespaceId(namespaceId, pageable);
    }

    @GetMapping("/resources/{resourceType}/{resourceId}")
    @PreAuthorize("hasAnyAuthority('AUDITOR','SECURITY_ADMIN','SUPER_ADMIN')")
    public Page<AuditLog> getByResource(
            @PathVariable String resourceType,
            @PathVariable String resourceId,
            @PageableDefault(size = 50) Pageable pageable) {
        return auditLogRepository.findByResourceTypeAndResourceId(resourceType, resourceId, pageable);
    }
}
