package com.example.backend;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
class ApiController {

    record CreateNote(@NotBlank @Size(max = 500) String text) {
    }

    record AdminOverview(int totalNotes, Map<String, Long> notesPerUser, List<NoteStore.Note> notes) {
    }

    private final NoteStore store;

    ApiController(NoteStore store) {
        this.store = store;
    }

    @GetMapping("/me")
    GatewayUser me(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser user) {
        return user;
    }

    @GetMapping("/notes")
    List<NoteStore.Note> myNotes(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser user) {
        return store.byOwner(user.id());
    }

    @PostMapping("/notes")
    ResponseEntity<NoteStore.Note> create(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser user,
                                          @Valid @RequestBody CreateNote body) {
        return ResponseEntity.status(HttpStatus.CREATED).body(store.add(user, body.text().strip()));
    }

    @DeleteMapping("/notes/{id}")
    ResponseEntity<Void> delete(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser user, @PathVariable String id) {
        return store.delete(id, user.id()) ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    // --- admin (nginx requires realm role "admin"; GatewayUserFilter re-checks) ---

    @GetMapping("/admin/notes")
    AdminOverview allNotes() {
        Collection<NoteStore.Note> all = store.all();
        Map<String, Long> perUser = all.stream()
                .collect(Collectors.groupingBy(NoteStore.Note::ownerName, Collectors.counting()));
        return new AdminOverview(all.size(), perUser, List.copyOf(all));
    }

    @DeleteMapping("/admin/notes/{id}")
    ResponseEntity<Void> adminDelete(@PathVariable String id) {
        return store.delete(id, null) ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }
}
