package org.tommap.springsecurityfirstsection.repository;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import org.tommap.springsecurityfirstsection.model.Notice;

import java.util.List;

@Repository
public interface NoticeRepository extends CrudRepository<Notice, Long> {
    @Query(value = "from Notice n where CURDATE() BETWEEN noticBegDt AND noticEndDt")
    List<Notice> findAllActiveNotices();

    //JPQL is very similar to SQL, but operates on entities, attributes, and relationships instead of tables and columns.
}
