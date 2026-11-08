package com.example.backend;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

/** In-memory store; data is lost on restart (it's a demo). */
@Component
class NoteStore {

    record Note(String id, String ownerId, String ownerName, String text, Instant createdAt) {
    }

    private final Map<String, Note> notes = new ConcurrentHashMap<>();

    Note add(GatewayUser owner, String text) {
        Note note = new Note(UUID.randomUUID().toString(), owner.id(), owner.username(), text, Instant.now());
        notes.put(note.id(), note);
        return note;
    }

    List<Note> byOwner(String ownerId) {
        return notes.values().stream()
                .filter(n -> n.ownerId().equals(ownerId))
                .sorted(Comparator.comparing(Note::createdAt).reversed())
                .toList();
    }

    List<Note> all() {
        return notes.values().stream().sorted(Comparator.comparing(Note::createdAt).reversed()).toList();
    }

    /** Removes the note if it exists and {@code ownerId} owns it (null = any owner). */
    boolean delete(String id, String ownerId) {
        Note note = notes.get(id);
        if (note == null || (ownerId != null && !note.ownerId().equals(ownerId))) {
            return false;
        }
        return notes.remove(id, note);
    }
}
